"""Building images (DESIGN 5.3): what runs in the builder, and the edge that runs it.

`core` is pure: it writes the scripts, apt sources and environment a build uses, from the plan and
the definition. `run` is the edge: it prepares a work directory, runs the builder container with no
network, and turns its output into an artifact and its records.
"""
