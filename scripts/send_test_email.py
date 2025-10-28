#!/usr/bin/env python3
"""Send a test email using the project's SMTP environment configuration.

Usage examples:
  # Dry-run (MAIL_ENABLED defaults to off) - safe, prints what would happen
  python3 scripts/send_test_email.py --to you@example.com --subject "Hi" --body "Hello"

  # Attempt to actually send (ensure SMTP_* env vars are set for your provider)
  python3 scripts/send_test_email.py --to you@example.com --subject "Hi" --body "Hello" --enable

The script uses the same env vars documented for the notifications module.
"""
from __future__ import annotations
import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send a test email using configured SMTP env vars")
    parser.add_argument("--to", required=True, help="Recipient email address")
    parser.add_argument("--subject", default="Test email from project", help="Email subject")
    parser.add_argument("--body", default="This is a test message.", help="Plain text body")
    parser.add_argument("--html", default=None, help="Optional HTML body")
    parser.add_argument("--enable", action="store_true", help="Temporarily enable MAIL_ENABLED for this run (actually send)")
    args = parser.parse_args(argv)

    # Ensure project root is importable when running from scripts/ directory
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    try:
        from backend.notifications import send_email, is_mail_enabled
    except Exception as e:
        print("Failed to import backend.notifications:", e, file=sys.stderr)
        return 2

    if args.enable:
        os.environ["MAIL_ENABLED"] = "1"

    print(f"MAIL_ENABLED={os.environ.get('MAIL_ENABLED')} (effective)")
    print(f"Sending to: {args.to}")

    ok = send_email(args.to, args.subject, args.body, args.html)
    if ok:
        print("send_email returned success (or did safe no-op)")
        return 0
    else:
        print("send_email reported failure; check logs and SMTP settings", file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
