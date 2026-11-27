# The bench, because there is no device.
#
# The design this measures says so plainly: nothing in this repository has
# been ordered, built or measured on a bench, the human has none, and a
# Docker container is what was meant by one. So this is the honest bench --
# arm64, Python 3.9 (the version CI pins and the implant runs), and the
# scout's own requirements and nothing else.
#
#     docker build -f tools/way_out_bench.Dockerfile -t raccoon-way-out-bench .
#     docker run --rm --platform linux/arm64 --cpus 4 --memory 4g \
#         -v "$PWD:/repo" -w /repo raccoon-way-out-bench --json
#
# `--cpus 4 --memory 4g` are the Pi 4 Model B's four cores and 4 GB. They
# are the closest a container gets, and they are not close: a Cortex-A72's
# clock is not an M-series or Xeon core's, and nothing here is bridging a
# host's traffic, drawing from a 13 W PoE budget or sharing an IP phone's
# thermal envelope. The script says that beside every second it prints.
#
# For the model arm, an Ollama beside it on loopback:
#
#     docker run -d --name way-out-ollama --platform linux/arm64 \
#         --cpus 4 --memory 4g -p 11434:11434 ollama/ollama
#     docker exec way-out-ollama ollama pull qwen2.5:0.5b
#     docker run --rm --platform linux/arm64 --cpus 4 --memory 4g \
#         --network host -v "$PWD:/repo" -w /repo raccoon-way-out-bench \
#         --model qwen2.5:0.5b --json
#
# The repository is mounted rather than copied: the bench measures the tree
# in front of you, and a COPY would measure whatever was there at build
# time.
FROM --platform=linux/arm64 python:3.9-slim

# scapy builds the replayed frames the parse cost is measured against, and
# PyYAML is the scout's other declared dependency. Installed from the
# scout's own file, so the bench cannot drift from what the implant needs.
COPY software/scout/requirements.txt /tmp/scout-requirements.txt
RUN pip install --no-cache-dir -r /tmp/scout-requirements.txt

ENV PYTHONPATH=/repo
ENTRYPOINT ["python3", "tools/way_out_bench.py"]
