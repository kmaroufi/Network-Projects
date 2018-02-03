from random import *
import struct
import rsa
import inspect
from rsa import PublicKey, PrivateKey
import queue

LOG_LEVEL = 4
PKEY_SERIALIZED_SIZE = 256


def bigint_to_bytes(i):
    """
    Serialize a large integer as network serialized bytes
    :param i:
    :return:
    """

    parts = []

    while i:
        parts.append(i & (2 ** 32 - 1))
        i >>= 32

    return struct.pack('>' + 32 * 'L', *parts)


def key_to_bytes(rsakey):
    """
    Convert rsa.PublicKey to its serialized bytes form
    :param rsakey: rsa.PublicKey
    :return: bytes
    """

    i = rsakey.n

    p1 = i & (2 ** 1024 - 1)
    p2 = i >> 1024

    return bigint_to_bytes(p1) + bigint_to_bytes(p2)


def bytes_to_key(mbytes):
    """
    Create rsa.PublicKey object from its serialized bytes form
    :param mbytes: bytes
    :return: rsa.PublicKey
    """

    parts = struct.unpack('>' + 64 * 'L', mbytes)

    res = 0
    for p in reversed(parts):
        res *= 2 ** 32
        res += p

    return PublicKey(res, 2 ** 16 + 1)


def log(*args, **kwargs):
    """
    Default log tool, whose use is highly recommended
    instead of the standard python "print" function

    :param args: any - print args
    :param kwargs: dict - options
    """
    curframe = inspect.currentframe()
    calframe = inspect.getouterframes(curframe, 2)
    callername = calframe[1][3]
    if kwargs.get("level", 1) <= LOG_LEVEL:
        if not kwargs.get("omitcallername", False):
            print(callername + ":", *args)
        else:
            print(*args)


def generate_random():
    res = bytearray(256)
    res[0] = 1
    for i in range(1, PKEY_SERIALIZED_SIZE):
        res[i] = randint(0, 1)
    return bytes(res)


def generate_graph(nodes, edges):
    adj_list = {}
    for node in nodes:
        adj_list[node] = []
    for edge in edges:
        adj_list[edge[0]] += [edge[1]]
    return adj_list


def find_min_hops(nodes, graph, s, t):
    visited = {}
    for node in nodes:
        visited[node] = (-1, [])
    boundery = queue.Queue()
    boundery.put(s)
    visited[s] = (0, [])
    while not boundery.empty():
        node = boundery.get()
        for adj_node in graph[node]:
            if visited[adj_node][0] == -1:
                visited[adj_node] = (visited[node][0] + 1, [node])
                boundery.put(adj_node)
            elif visited[adj_node][0] == visited[node][0] + 1:
                visited[adj_node][1] += [node]

    # print(visited)
    return calc(visited, s, t, [])


def calc(visited, s, t, path):
    if len(visited[t][1]) == 0:
        return [path]
    paths = []
    for parent in visited[t][1]:
        paths += calc(visited, s, parent, [parent] + path)
    return paths


def min_weight(paths, config):
    min_path = paths[0]
    weight = calc_path_weight(paths[0], config)
    for path in paths:
        if calc_path_weight(path, config) < weight:
            weight = calc_path_weight(path, config)
            min_path = path
    return min_path


def calc_path_weight(path, config):
    weight = 0
    for i in range(len(path)-1):
        weight += config.latency(path[i], path[i+1])
    return weight


if __name__ == "__main__":
    a, b = rsa.newkeys(2048)
    print(a)
    s = key_to_bytes(a)
    r = bytes_to_key(s)
    print(r)
    print(generate_random())
