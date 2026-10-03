"""Read-only Neo4j access for the risk package.

Frozen contract: get_driver(), run().
"""
import os

from neo4j import GraphDatabase


def get_driver():
    password = os.environ.get("NEO4J_PASSWORD")
    if not password:
        raise RuntimeError(
            "NEO4J_PASSWORD is not defined. Copy .env.example to .env "
            "and set it, or set it in the current shell."
        )
    return GraphDatabase.driver(
        os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        auth=(os.getenv("NEO4J_USER", "neo4j"), password),
    )


def run(session, cypher, **params):
    """Read-only helper. Returns list[dict]."""
    return [r.data() for r in session.run(cypher, **params)]
