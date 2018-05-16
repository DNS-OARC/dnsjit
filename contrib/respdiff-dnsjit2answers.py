#!/usr/bin/env python3

import sys
import lmdb
import pickle

WireFormat = bytes

class Reply:
    def __init__(self, wire: WireFormat, duration: float) -> None:
        self.wire = wire
        self.duration = duration

def main():
    with lmdb.Environment(path=sys.argv[1], readonly=False, max_dbs=10) as env:
        try:
            db = env.open_db(key=b'answers', create=False)
            with env.begin(write=True) as txn:
                txn.drop(db)
        except lmdb.NotFoundError:
            pass

        adb = env.open_db(b'answers', create=True)
        db = env.open_db(b'queries')
        resp = env.open_db(b'dnsjit')
        rtxn = env.begin(resp)

        atxn = env.begin(adb, write=True)
        with env.begin(db) as txn:
            cur = txn.cursor(db)
            for key in cur.iternext(keys=True, values=False):
                replies = {}
                okey = bytearray(key)
                okey[0] += 1
                replies[sys.argv[2]] = Reply(rtxn.get(okey), 0)
                rkey = bytearray(key)
                rkey[0] += 2
                replies[sys.argv[3]] = Reply(rtxn.get(rkey), 0)
                atxn.put(key, pickle.dumps(replies))
        atxn.commit()

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("usage: {} <lmdb path> <original response server> <received response server>".format(sys.argv[0]))
        print("  NOTE: server names need to be the same as in respdiff.cfg")
        sys.exit(1)
    main()
