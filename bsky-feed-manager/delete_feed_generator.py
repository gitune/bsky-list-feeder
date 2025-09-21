#!/usr/bin/env python
# coding: UTF-8
#
# delete app.bsky.feed.generator record
# using feed_id from generator.json file
#
# Env:
#   BSKY_ID / BSKY_APPPASSWORD must be set

import sys, json, os
from atproto import Client, Session, SessionEvent

SESSION_FILE = 'bsky_session.txt'

def get_session():
    try:
        with open(SESSION_FILE) as f:
            return f.read()
    except FileNotFoundError:
        return None

def save_session(session_string: str):
    with open(SESSION_FILE, 'w') as f:
        f.write(session_string)

def on_session_change(event: SessionEvent, session: Session):
    if event in (SessionEvent.CREATE, SessionEvent.REFRESH):
        save_session(session.export())

def init_client() -> Client:
    client = Client()
    client.on_session_change(on_session_change)

    session_string = get_session()
    if session_string:
        client.login(session_string=session_string)
    else:
        client.login(os.environ['BSKY_ID'], os.environ['BSKY_APPPASSWORD'])

    return client

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python delete_feed_generator.py <generator.json>")
        sys.exit(1)

    generator_json_path = sys.argv[1]

    # feed_id（rkey）はファイル名から取得する想定にします
    # 例: ./myfeed/generator.json → feed_id = "myfeed"
    feed_id = os.path.basename(os.path.dirname(os.path.abspath(generator_json_path)))
    if not feed_id:
        print("Could not determine feed_id from generator.json path")
        sys.exit(1)

    client = init_client()

    client.com.atproto.repo.delete_record(
        data={
            "repo": client.me.did,
            "collection": "app.bsky.feed.generator",
            "rkey": feed_id
        }
    )

    print(f"Deleted feed generator record: {feed_id}")

