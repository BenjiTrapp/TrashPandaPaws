# The lab's beacon: the interpreter and nothing else.
#
# `requests` was in the plan for this image and is not here, on
# measurement: beacon.py imports only the standard library (its HTTP
# session is `_HttpSession` over urllib, and says so), and it imports
# cleanly on a bare python:3.12-slim. An unused dependency would also be
# one more thing for the lab to be wrong about.
#
# The beacon must not have flask, cryptography or anything else the server
# imports: a beacon that can import the server is a beacon that might. The
# stock image has none of them, and test_e2e_lab fails if this file ever
# installs them.
#
# No source here either; see teamserver.Dockerfile.
FROM python:3.12-slim
