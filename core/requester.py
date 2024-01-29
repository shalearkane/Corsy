import urllib3
import requests
from core.colors import bad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Added better error handling.
# Added verbose options.


def curlify(request):
    command = "curl -X {method} -H {headers} -d '{data}' '{uri}'"
    method = request.method
    uri = request.url
    data = request.body
    headers = ['"{0}: {1}"'.format(k, v) for k, v in request.headers.items()]
    headers = " -H ".join(headers)
    return command.format(method=method, headers=headers, data=data, uri=uri)


def requester(url, scheme, headers, origin):
    headers["Origin"] = origin
    try:
        response = requests.get(url, headers=headers, verify=False)
        headers = response.headers
        for key, value in headers.items():
            if key.lower() == "access-control-allow-origin":
                return (
                    headers,
                    response.text,
                    response.status_code,
                    curlify(response.request),
                )
    except requests.exceptions.RequestException as e:
        if "Failed to establish a new connection" in str(e):
            print("%s %s is unreachable" % (bad, url))
        elif "requests.exceptions.TooManyRedirects:" in str(e):
            print("%s %s has too many redirects" % (bad, url))
    return {}
