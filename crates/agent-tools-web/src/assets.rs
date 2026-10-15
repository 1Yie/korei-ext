//! Asset tools for document production — `image_search`, `web_download`,
//! `view_image`. Registered only into the `office` registry alongside the
//! `office_*` wrappers.
//!
//! The flow they enable: `image_search` finds license-clean pictures via
//! Openverse (keyless API) → `web_download` fetches the chosen URL into the
//! workspace through the same `net` guards as `web_fetch` (SSRF, byte cap)
//! → `office_add --type picture` places it in the document. `view_image`
//! lets the model *see* any workspace image — user-dropped assets,
//! downloaded files — through the `ToolResult.images` channel `screenshot`
//! and the composer attachments already use. A text-only model just keeps
//! the path text, same degradation contract.

use std::sync::Arc;

use futures::FutureExt;
use serde::Deserialize;

use crate::net;
use agent_capabilities::WorkspaceCtx;
use agent_capabilities::WorkspacePaths;
use agent_tool::{schema_for, ToolError, ToolResult, ToolSpec};

/// Refuse to attach images larger than this — bigger payloads mostly break
/// the wire, not inform it (providers cap ~5 MB/part anyway).
const MAX_IMAGE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ImageSearchArgs {
    /// What to search for (English queries work best).
    query: String,
    /// How many candidates to return per engine (default 8, max 20).
    count: Option<u32>,
    /// Which engine(s) to query: `auto` (default — try all and merge),
    /// `wikimedia` (license-clean, great for landscapes/objects/landmarks)
    /// or `bing` (broad web coverage — brands, products, CN content).
    engine: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WebDownloadArgs {
    /// The HTTP or HTTPS URL to download. Private/loopback/reserved
    /// addresses are refused; redirects are re-validated.
    url: String,
    /// Workspace-relative destination path, e.g. `assets/logo.png`. Parent
    /// directories are created. Keep the real extension so officecli and
    /// `view_image` recognize the format. Downloads are capped at 10 MB.
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ViewImageArgs {
    /// Workspace-relative path to an image file (png/jpg/jpeg/gif/webp/bmp)
    /// up to 8 MB. The image is attached to the tool result — the model sees
    /// it directly when it accepts image input.
    file: String,
}

pub fn specs<C: WorkspaceCtx>() -> Vec<ToolSpec<C>> {
    vec![image_search(), web_download(), view_image()]
}

/// One search hit, normalized across engines so the output format stays
/// uniform regardless of where the image was found.
struct Hit {
    title: String,
    /// Primary download URL — the reliable one (Bing CDN / thumb.php).
    url: String,
    /// Fallback/original URL — higher resolution but on a CDN that may be
    /// unreachable from this network.
    alt: String,
    /// "WxH" when the engine reports dimensions.
    size: String,
    /// License label (wikimedia only; bing results are license-unknown).
    license: String,
    /// Source page URL.
    page: String,
}

fn image_search<C: WorkspaceCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "image_search",
        schema: schema_for::<ImageSearchArgs>(
            "Search the internet for images across multiple engines. `auto` \
             (default) queries all engines concurrently and merges: \
             `wikimedia` = license-clean Commons media (landmarks, objects, \
             nature — cite the license when used), `bing` = broad web crawl \
             (brands, products, local/CN content — license unknown, treat as \
             fair-use reference). Each hit gives a reliable `url` to feed \
             `web_download` plus an `alt` original. Pick → `web_download` → \
             `office_add` --type picture.",
        ),
        readonly: true,
        class: agent_tool::ToolClass::Observation,
        network: true,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: ImageSearchArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("image_search args: {e}")))?;
                let count = a.count.unwrap_or(8).clamp(1, 20);
                let engine = a
                    .engine
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("auto")
                    .to_lowercase();

                let mut hits: Vec<(&'static str, Hit)> = Vec::new();
                let mut errors: Vec<String> = Vec::new();

                match engine.as_str() {
                    "wikimedia" | "commons" => {
                        hits.extend(
                            search_wikimedia(&ctx, &a.query, count)
                                .await?
                                .into_iter()
                                .map(|h| ("wikimedia", h)),
                        );
                    }
                    "bing" => {
                        hits.extend(
                            search_bing(&ctx, &a.query, count)
                                .await?
                                .into_iter()
                                .map(|h| ("bing", h)),
                        );
                    }
                    "auto" | "all" => {
                        let (wm, bg) = futures::join!(
                            search_wikimedia(&ctx, &a.query, count),
                            search_bing(&ctx, &a.query, count),
                        );
                        match wm {
                            Ok(v) => hits.extend(v.into_iter().map(|h| ("wikimedia", h))),
                            Err(e) => errors.push(format!("wikimedia: {e}")),
                        }
                        match bg {
                            Ok(v) => hits.extend(v.into_iter().map(|h| ("bing", h))),
                            Err(e) => errors.push(format!("bing: {e}")),
                        }
                        if hits.is_empty() && errors.len() == 2 {
                            return Err(ToolError::Failed(format!(
                                "all engines failed — {}",
                                errors.join("; ")
                            )));
                        }
                    }
                    other => {
                        return Err(ToolError::Args(format!(
                            "unknown engine '{other}' — use auto|wikimedia|bing"
                        )))
                    }
                }

                if hits.is_empty() {
                    return Ok(ToolResult::text(format!(
                        "no results for {:?} — try a broader or English query",
                        a.query
                    )));
                }
                let mut out = String::new();
                let mut cur = "";
                for (i, (eng, h)) in hits.iter().enumerate() {
                    if *eng != cur {
                        cur = eng;
                        out.push_str(&format!("\n[{eng}]\n"));
                    }
                    out.push_str(&format!("{}. {}\n", i + 1, h.title));
                    out.push_str(&format!("   url: {}\n", h.url));
                    if !h.alt.is_empty() && h.alt != h.url {
                        out.push_str(&format!("   alt: {}\n", h.alt));
                    }
                    if !h.size.is_empty() {
                        out.push_str(&format!("   size: {}\n", h.size));
                    }
                    if !h.license.is_empty() {
                        out.push_str(&format!("   license: {}\n", h.license));
                    }
                    if !h.page.is_empty() {
                        out.push_str(&format!("   page: {}\n", h.page));
                    }
                }
                for e in &errors {
                    out.push_str(&format!("\n(engine failed: {e})\n"));
                }
                // Result titles/URLs are untrusted external text — fence them
                // so the model treats them as data, not instructions.
                Ok(ToolResult::text(format!(
                    "[BEGIN UNTRUSTED SEARCH RESULTS]\n{out}\n[END UNTRUSTED SEARCH RESULTS]\n\
                     `web_download` the chosen `url` (fall back to `alt`), then \
                     `office_add` --type picture (src=<workspace path>)."
                )))
            }
            .boxed()
        }),
    }
}

/// Wikimedia Commons: free-license media via the public action API. The
/// `thumb.php` URL serves a bounded-width copy on the SAME domain as the
/// API — useful when `upload.wikimedia.org` is unreachable.
async fn search_wikimedia<C: WorkspaceCtx>(
    ctx: &Arc<C>,
    query: &str,
    count: u32,
) -> Result<Vec<Hit>, ToolError> {
    let url = format!(
        "https://commons.wikimedia.org/w/api.php?action=query\
         &generator=search&gsrnamespace=6&prop=imageinfo\
         &iiprop=url%7Csize%7Cmime%7Cextmetadata&format=json\
         &gsrsearch={}&gsrlimit={}",
        urlform(query),
        count,
    );
    let ua = net::user_agent(ctx.app_paths()?.app_name());
    let resp = net::fetch(&url, "application/json", ctx.cancel_flag(), &ua).await?;
    if !resp.status.is_success() {
        return Err(ToolError::Failed(format!("HTTP {}", resp.status)));
    }
    let json: serde_json::Value = serde_json::from_slice(&resp.body)
        .map_err(|e| ToolError::Failed(format!("bad search response: {e}")))?;
    let mut hits = Vec::new();
    if let Some(pages) = json["query"]["pages"].as_object() {
        let mut pages: Vec<_> = pages.values().collect();
        pages.sort_by_key(|p| p["index"].as_u64().unwrap_or(u64::MAX));
        for p in pages {
            let title = p["title"].as_str().unwrap_or("").to_string();
            let fname = title.strip_prefix("File:").unwrap_or(&title).to_string();
            let ii = &p["imageinfo"][0];
            let w = ii["width"].as_u64().unwrap_or(0);
            let h = ii["height"].as_u64().unwrap_or(0);
            let mime = ii["mime"].as_str().unwrap_or("");
            let lic = ii["extmetadata"]["LicenseShortName"]["value"]
                .as_str()
                .unwrap_or("")
                .to_string();
            hits.push(Hit {
                title,
                url: format!(
                    "https://commons.wikimedia.org/w/thumb.php?f={}&width=1280",
                    urlform(&fname)
                ),
                alt: format!(
                    "https://commons.wikimedia.org/wiki/Special:FilePath/{}",
                    urlform(&fname)
                ),
                size: if w > 0 {
                    format!("{w}x{h} {mime}")
                } else {
                    String::new()
                },
                license: lic,
                page: ii["descriptionurl"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    Ok(hits)
}

/// Bing Images: scrape `cn.bing.com` — the `m="{...}"` attribute on each
/// result anchor carries JSON with `turl` (Bing CDN thumb — reachable),
/// `murl` (original image — may be on a foreign CDN) and `purl` (page).
async fn search_bing<C: WorkspaceCtx>(
    ctx: &Arc<C>,
    query: &str,
    count: u32,
) -> Result<Vec<Hit>, ToolError> {
    let url = format!(
        "https://cn.bing.com/images/search?q={}&form=HDRSC2&first=1",
        urlform(query)
    );
    let ua = net::user_agent(ctx.app_paths()?.app_name());
    let resp = net::fetch(&url, "text/html", ctx.cancel_flag(), &ua).await?;
    if !resp.status.is_success() {
        return Err(ToolError::Failed(format!("HTTP {}", resp.status)));
    }
    let html = String::from_utf8_lossy(&resp.body);
    Ok(parse_bing_hits(&html, count))
}

/// Extract hits from `m="{...}"` result attributes — inner quotes arrive
/// HTML-escaped, so the first raw `"` after `m="` terminates the value.
fn parse_bing_hits(html: &str, count: u32) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut rest = html;
    while hits.len() < count as usize {
        let Some(pos) = rest.find("m=\"") else {
            break;
        };
        let after = &rest[pos + 3..];
        if !after.starts_with('{') {
            rest = &rest[pos + 3..];
            continue;
        }
        let Some(end) = after.find('"') else {
            break;
        };
        let raw = &after[..end];
        rest = &after[end + 1..];
        let unescaped = raw
            .replace("&quot;", "\"")
            .replace("&amp;", "&")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">");
        let Ok(m) = serde_json::from_str::<serde_json::Value>(&unescaped) else {
            continue;
        };
        let get = |k: &str| m[k].as_str().unwrap_or("").to_string();
        let turl = get("turl");
        if turl.is_empty() {
            continue;
        }
        hits.push(Hit {
            title: get("t"),
            url: turl,
            alt: get("murl"),
            size: String::new(), // bing m= carries no dimensions
            license: String::new(),
            page: get("purl"),
        });
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `m="` attrs that don't start with `{` and malformed JSON are skipped;
    /// valid entries decode into hits with turl as the primary URL.
    #[test]
    fn bing_m_attr_extraction_skips_noise() {
        let html = concat!(
            r#"<a class="x" m="notjson"><a class="y" m="{broken}">"#,
            r#"<a class="iusc" m="{&quot;t&quot;:&quot;Milk Tea&quot;,&quot;turl&quot;:&quot;https://ts1.mm.bing.net/th?id=1&quot;,&quot;murl&quot;:&quot;https://orig/x.jpg&quot;,&quot;purl&quot;:&quot;https://pg/x&quot;}">"#,
            r#"<a class="iusc" m="{&quot;t&quot;:&quot;Bob&quot;,&quot;turl&quot;:&quot;https://ts2.mm.bing.net/th?id=2&quot;}">"#,
            r#"<a class="iusc" m="{&quot;t&quot;:&quot;NoThumb&quot;,&quot;murl&quot;:&quot;https://orig/y.jpg&quot;}">"#,
        );
        let hits = parse_bing_hits(html, 10);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].title, "Milk Tea");
        assert_eq!(hits[0].url, "https://ts1.mm.bing.net/th?id=1");
        assert_eq!(hits[0].alt, "https://orig/x.jpg");
        assert_eq!(hits[1].url, "https://ts2.mm.bing.net/th?id=2");
    }

    /// The `count` cap truncates rather than walking the whole page.
    #[test]
    fn bing_hits_respect_count() {
        let html = concat!(
            r#"<a m="{&quot;turl&quot;:&quot;u1&quot;}">"#,
            r#"<a m="{&quot;turl&quot;:&quot;u2&quot;}">"#,
            r#"<a m="{&quot;turl&quot;:&quot;u3&quot;}">"#,
        );
        let hits = parse_bing_hits(html, 2);
        assert_eq!(hits.len(), 2);
    }

    /// Percent-encoding keeps queries URL-safe.
    #[test]
    fn urlform_encodes() {
        assert_eq!(urlform("milk tea&x"), "milk%20tea%26x");
    }
}

fn web_download<C: WorkspaceCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "web_download",
        schema: schema_for::<WebDownloadArgs>(
            "Download a file from a public URL into the workspace (10 MB cap). \
             Use it for images/assets found with `image_search` or `web_fetch`. \
             When the file is an image it is also attached to the result so \
             you can verify what was fetched.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: true,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: WebDownloadArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("web_download args: {e}")))?;
                let ua = net::user_agent(ctx.app_paths()?.app_name());
                let resp = net::fetch(&a.url, "*/*", ctx.cancel_flag(), &ua).await?;
                if !resp.status.is_success() {
                    return Err(ToolError::Failed(format!(
                        "download failed: HTTP {}",
                        resp.status
                    )));
                }
                // `fetch` stops reading at the size cap. Writing that prefix
                // would leave a corrupt file that still reports success.
                if resp.body_truncated {
                    return Err(ToolError::Failed(format!(
                        "download exceeds the 10 MB limit — nothing was written. \
                         Pick a smaller file (URL: {})",
                        a.url
                    )));
                }
                let dest = ctx.resolve(&a.path)?;
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| ToolError::Failed(format!("mkdir {parent:?}: {e}")))?;
                }
                std::fs::write(&dest, &resp.body)
                    .map_err(|e| ToolError::Failed(format!("write {dest:?}: {e}")))?;
                let shown = dest.strip_prefix(ctx.root()?).unwrap_or(&dest).display();
                let mut res = ToolResult::text(format!(
                    "downloaded: {shown}  ({} bytes, {})",
                    resp.body.len(),
                    if resp.content_type.is_empty() {
                        "unknown type".to_string()
                    } else {
                        resp.content_type.clone()
                    },
                ));
                // Vision bonus: attach the image so the model sees exactly
                // what it downloaded (engine drops it for text-only models).
                if resp.content_type.starts_with("image/") {
                    if let Some(img) = agent_llm_core::types::ImageRef::for_path(dest) {
                        res.images.push(img);
                    }
                }
                Ok(res)
            }
            .boxed()
        }),
    }
}

fn view_image<C: WorkspaceCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "view_image",
        schema: schema_for::<ViewImageArgs>(
            "Look at an image file in the workspace — user-provided assets, \
             downloaded pictures, generated renders. The image is attached to \
             the result so you see its contents directly (png/jpg/jpeg/gif/\
             webp/bmp, ≤8 MB).",
        ),
        readonly: true,
        class: agent_tool::ToolClass::Observation,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: ViewImageArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("view_image args: {e}")))?;
                let path = ctx.resolve(&a.file)?;
                let meta = std::fs::metadata(&path)
                    .map_err(|e| ToolError::Failed(format!("cannot stat {}: {e}", a.file)))?;
                if meta.len() > MAX_IMAGE_BYTES {
                    return Err(ToolError::Failed(format!(
                        "image is {:.1} MB (> 8 MB) — downscale it first \
                         (e.g. `magick <in> -resize 1600x <out>`)",
                        meta.len() as f64 / (1024.0 * 1024.0)
                    )));
                }
                let img =
                    agent_llm_core::types::ImageRef::for_path(path.clone()).ok_or_else(|| {
                        ToolError::Args(format!(
                            "not a viewable image type: {} (want png/jpg/jpeg/gif/webp/bmp)",
                            a.file
                        ))
                    })?;
                let shown = path.strip_prefix(ctx.root()?).unwrap_or(&path).display();
                let mut res = ToolResult::text(format!(
                    "image: {shown}  ({} bytes, {})",
                    meta.len(),
                    img.media_type,
                ));
                res.images.push(img);
                Ok(res)
            }
            .boxed()
        }),
    }
}

/// Minimal percent-encoding for query parameters — query/values only.
fn urlform(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push_str("%20"),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}
