def main(request, response):
    """
    Handler for WAICT max-age tests.
    ?set&max-age=N&mode=MODE: sends WAICT header with specified max-age and mode
    ?set&max-age=N: sends WAICT header with specified max-age (default mode=enforce)
    ?set (no max-age): sends WAICT header with max-age=90 (default mode=enforce)
    (no params): NO WAICT header
    """
    headers = [
        (b"Content-Type", b"text/html; charset=utf-8")
    ]

    if b"set" in request.GET:
        # Get max-age value from query params, default to 90
        max_age = request.GET.get(b"max-age", b"90")
        # Get mode from query params, default to enforce
        mode = request.GET.get(b"mode", b"enforce")
        header_value = b"manifest=\"waict-manifest.json\", blocked-destinations=(image), mode=" + mode + b", max-age=" + max_age
        headers.append((b"Integrity-Policy-WAICT-v1", header_value))

    # Return simple HTML with test image
    html = b"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>WAICT Max-age Test Page</title>
</head>
<body>
    <img id="test-image" src="incorrect.png">
</body>
</html>"""

    return headers, html
