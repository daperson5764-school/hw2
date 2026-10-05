import os
import sys

# project root = parent of this tests/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import handshake as hs


@pytest.fixture(scope="session")
def material():
    return {
        "params":    hs.load_params(),
        "gw_rsa":    rsa.generate_private_key(public_exponent=65537, key_size=3072),
        "nd_rsa":    rsa.generate_private_key(public_exponent=65537, key_size=3072),
        "wrong_rsa": rsa.generate_private_key(public_exponent=65537, key_size=3072),
    }


@pytest.fixture
def make_parties(material):
    """Factory: returns (gateway, node) wired to trust each other."""
    def _make():
        gw = hs.Party("gateway.csce465.local", hs.ROLE_GATEWAY,
                      material["gw_rsa"], material["params"])
        nd = hs.Party("node.csce465.local", hs.ROLE_NODE,
                      material["nd_rsa"], material["params"])
        gw.trust(nd.identity, nd.rsa_public)
        nd.trust(gw.identity, gw.rsa_public)
        return gw, nd
    return _make


@pytest.fixture
def session_keys(make_parties):
    """Run one honest handshake and hand back its derived keys + session_id."""
    gw, nd = make_parties()
    kg, _ = hs.run_handshake(gw, nd, verbose=False)
    return {
        "session_id": kg["session_id"],
        "k_g2n_enc":  kg["K_g2n_enc"], "k_g2n_mac": kg["K_g2n_mac"],
        "k_n2g_enc":  kg["K_n2g_enc"], "k_n2g_mac": kg["K_n2g_mac"],
    }
