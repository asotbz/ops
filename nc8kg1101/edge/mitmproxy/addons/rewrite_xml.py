# rewrite_xml.py
from mitmproxy import http
import xml.etree.ElementTree as ET
import base64, os

PSK = os.environ.get("ORX_PSK", "changeme")
NGINX_BASE = os.environ.get("ORX_BASE", "https://orx.invalid/proxy")

def response(flow: http.HTTPFlow) -> None:
    ctype = flow.response.headers.get("content-type", "")
    if "xml" not in ctype.lower():
        return

    try:
        root = ET.fromstring(flow.response.content)

        for elem in root.iter():
            if elem.text and elem.text.startswith(("http://", "https://")):
                elem.text = rewrite(elem.text)
            for k, v in list(elem.attrib.items()):
                if v and v.startswith(("http://", "https://")):
                    elem.attrib[k] = rewrite(v)

        # Re-serialize XML to string
        flow.response.text = ET.tostring(root, encoding="unicode")
    except Exception as e:
        flow.log.warn(f"XML rewrite failed: {e}")

def rewrite(url: str) -> str:
    # Base64url encode
    b64 = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{NGINX_BASE}/{PSK}/{b64}"
