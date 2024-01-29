import sys
import time

from core.requester import requester
from core.utils import host, load_json

details = load_json(sys.path[0] + "/db/details.json")


def passive_tests(url, headers) -> dict:
    root = host(url)
    acao_header, acac_header = headers.get(
        "access-control-allow-origin", None
    ), headers.get("access-control-allow-credentials", None)
    if acao_header == "*":
        info = details["wildcard value"]
        info["acao header"] = acao_header
        info["acac header"] = acac_header
        return {url: info}
    if root:
        if host(acao_header) and root != host(acao_header):
            info = details["third party allowed"]
            info["acao header"] = acao_header
            info["acac header"] = acac_header
            return {url: info}

    return {}


def active_tests(url, root, scheme, header_dict, delay):
    origin = scheme + "://" + root
    headers, body, status_code, curl = requester(url, scheme, header_dict, origin)
    acao_header, acac_header = headers.get(
        "access-control-allow-origin", None
    ), headers.get("access-control-allow-credentials", None)
    if acao_header is None:
        return

    origin = scheme + "://" + "example.com"
    headers, body, status_code, curl = requester(url, scheme, header_dict, origin)
    acao_header, acac_header = headers.get(
        "access-control-allow-origin", None
    ), headers.get("access-control-allow-credentials", None)
    if acao_header and acao_header == (origin):
        info = details["origin reflected"]
        info["acao header"] = acao_header
        info["acac header"] = acac_header
        return {url: info}
    time.sleep(delay)

    origin = scheme + "://" + root + ".example.com"
    headers, body, status_code, curl = requester(url, scheme, header_dict, origin)
    acao_header, acac_header = headers.get(
        "access-control-allow-origin", None
    ), headers.get("access-control-allow-credentials", None)
    if acao_header and acao_header == (origin):
        info = details["post-domain wildcard"]
        info["acao header"] = acao_header
        info["acac header"] = acac_header
        return {url: info}
    time.sleep(delay)

    origin = scheme + "://d3v" + root
    headers, body, status_code, curl = requester(url, scheme, header_dict, origin)
    acao_header, acac_header = headers.get(
        "access-control-allow-origin", None
    ), headers.get("access-control-allow-credentials", None)
    if acao_header and acao_header == (origin):
        info = details["pre-domain wildcard"]
        info["acao header"] = acao_header
        info["acac header"] = acac_header
        return {url: info}
    time.sleep(delay)

    origin = "null"
    headers, body, status_code, curl = requester(url, "", header_dict, origin)
    acao_header, acac_header = headers.get(
        "access-control-allow-origin", None
    ), headers.get("access-control-allow-credentials", None)
    if acao_header and acao_header == "null":
        info = details["null origin allowed"]
        info["acao header"] = acao_header
        info["acac header"] = acac_header
        return {url: info}
    time.sleep(delay)

    origin = scheme + "://" + root + "_.example.com"
    headers, body, status_code, curl = requester(url, scheme, header_dict, origin)
    acao_header, acac_header = headers.get(
        "access-control-allow-origin", None
    ), headers.get("access-control-allow-credentials", None)
    if acao_header and acao_header == origin:
        info = details["unrecognized underscore"]
        info["acao header"] = acao_header
        info["acac header"] = acac_header
        return {url: info}
    time.sleep(delay)

    origin = scheme + "://" + root + "%60.example.com"
    headers, body, status_code, curl = requester(url, scheme, header_dict, origin)
    acao_header, acac_header = headers.get(
        "access-control-allow-origin", None
    ), headers.get("access-control-allow-credentials", None)
    if acao_header and "`.example.com" in acao_header:
        info = details["broken parser"]
        info["acao header"] = acao_header
        info["acac header"] = acac_header
        return {url: info}
    time.sleep(delay)

    if root.count(".") > 1:
        origin = scheme + "://" + root.replace(".", "x", 1)
        headers, body, status_code, curl = requester(url, scheme, header_dict, origin)
        acao_header, acac_header = headers.get(
            "access-control-allow-origin", None
        ), headers.get("access-control-allow-credentials", None)
        if acao_header and acao_header == origin:
            info = details["unescaped regex"]
            info["acao header"] = acao_header
            info["acac header"] = acac_header
            return {url: info}
        time.sleep(delay)
    origin = "http://" + root
    headers, body, status_code, curl = requester(url, "http", header_dict, origin)
    acao_header, acac_header = headers.get(
        "access-control-allow-origin", None
    ), headers.get("access-control-allow-credentials", None)
    if acao_header and acao_header.startswith("http://"):
        info = details["http origin allowed"]
        info["acao header"] = acao_header
        info["acac header"] = acac_header
        return {url: info}
    else:
        passive_result = passive_tests(url, headers)
        passive_result[url]["response_headers"] = dict(headers)
        passive_result[url]["response_body"] = body
        passive_result[url]["status_code"] = status_code
        passive_result[url]["request_header"] = header_dict
        passive_result[url]["uri"] = url
        passive_result[url]["validate"] = curl
        return passive_result
