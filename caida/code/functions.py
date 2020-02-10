#!/usr/bin/env python3
# encoding: utf-8
def conf_ini(initiator, filters, dici):
    for key in filters.keys():
        for words in initiator:
            if key in words:
                pos = initiator.index(key)
                dici.append((initiator[pos:pos+int(filters.get(words))]))
                break
    return dici
def test(data):
    data = iter(data)
    while True:
        filtro = next(data)
        pos = next(data)
        yield filtro, pos