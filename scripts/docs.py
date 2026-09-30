#!/usr/bin/env python3
"""Google Docs API — read document content via domain-wide delegation."""

import argparse
import json
import sys
from typing import Optional

from auth import get_service


def get_document(
    user: str,
    document_id: str,
) -> dict:
    """Get document metadata and structure.

    Args:
        user: Email address (impersonated via DWD).
        document_id: Google Docs document ID.

    Returns:
        Dict with document metadata.
    """
    service = get_service("docs", impersonate=user)
    doc = service.documents().get(documentId=document_id, includeTabsContent=True).execute()

    return {
        "document_id": doc.get("documentId", ""),
        "title": doc.get("title", ""),
        "revision_id": doc.get("revisionId", ""),
        "body_text": _extract_text(doc),
    }


def get_text(
    user: str,
    document_id: str,
) -> dict:
    """Get just the plain text content of a document.

    Args:
        user: Email address.
        document_id: Google Docs document ID.

    Returns:
        Dict with document text.
    """
    service = get_service("docs", impersonate=user)
    doc = service.documents().get(documentId=document_id, includeTabsContent=True).execute()

    return {
        "document_id": doc.get("documentId", ""),
        "title": doc.get("title", ""),
        "text": _extract_text(doc),
    }


def _extract_text(doc: dict) -> str:
    """Extract plain text from a Google Docs document, including all tabs.

    Docs with multiple tabs (2024+) only return the first tab in ``body``
    unless ``includeTabsContent=True``; then content lives under
    ``tabs[].documentTab.body`` (and ``childTabs``). Tables are walked too.
    """
    tabs = doc.get("tabs")
    if not tabs:
        return _content_text(doc.get("body", {}).get("content", []))
    walked = list(_walk_tabs(tabs))
    label = len(walked) > 1  # label every tab (incl. leaf child tabs) when there is more than one
    parts = []
    for tab in walked:
        title = tab.get("tabProperties", {}).get("title", "")
        text = _content_text(tab.get("documentTab", {}).get("body", {}).get("content", []))
        parts.append(f"=== {title} ===\n{text}" if label else text)
    return "\n".join(parts)


def _walk_tabs(tabs: list):
    for tab in tabs:
        yield tab
        yield from _walk_tabs(tab.get("childTabs", []))


def _content_text(content: list) -> str:
    text_parts = []
    for element in content:
        if "paragraph" in element:
            for elem in element["paragraph"].get("elements", []):
                text_run = elem.get("textRun")
                if text_run:
                    text_parts.append(text_run.get("content", ""))
        elif "table" in element:
            for row in element["table"].get("tableRows", []):
                cells = [_content_text(cell.get("content", [])).strip() for cell in row.get("tableCells", [])]
                text_parts.append("\t".join(cells) + "\n")
        elif "tableOfContents" in element:
            text_parts.append(_content_text(element["tableOfContents"].get("content", [])))
    return "".join(text_parts)


def main():
    parser = argparse.ArgumentParser(description="Google Docs read")
    sub = parser.add_subparsers(dest="command", required=True)

    # get
    p_get = sub.add_parser("get", help="Get document with full text")
    p_get.add_argument("--user", required=True)
    p_get.add_argument("--id", required=True, help="Document ID")

    # text
    p_text = sub.add_parser("text", help="Get document text only")
    p_text.add_argument("--user", required=True)
    p_text.add_argument("--id", required=True, help="Document ID")

    args = parser.parse_args()

    try:
        if args.command == "get":
            result = get_document(args.user, args.id)
        elif args.command == "text":
            result = get_text(args.user, args.id)
        else:
            result = {"error": f"Unknown command: {args.command}"}

        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
