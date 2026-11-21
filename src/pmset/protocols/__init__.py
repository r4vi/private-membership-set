"""Built-in concrete Private Set Membership (PMSet) protocol implementations.

Importing this package registers all 11 canonical PMSet implementations into
the global :mod:`pmset.core.registry`.
"""

from pmset.core.registry import register_protocol
from pmset.protocols.cuckoo_pir import (
    CuckooOPRFPIRClient,
    CuckooOPRFPIRProtocol,
    CuckooOPRFPIRServer,
)
from pmset.protocols.elgamal_eq import (
    ElGamalEqualityClient,
    ElGamalEqualityProtocol,
    ElGamalEqualityServer,
)
from pmset.protocols.fnp import (
    FNPPaillierClient,
    FNPPaillierProtocol,
    FNPPaillierServer,
)
from pmset.protocols.multiserver_pir import (
    MultiServerOPRFPIRClient,
    MultiServerOPRFPIRServer,
    ShamirMultiServerPIRProtocol,
    TwoServerDPFPIRProtocol,
)
from pmset.protocols.oprf_filter import (
    ECDHOPRFFilterClient,
    ECDHOPRFFilterProtocol,
    ECDHOPRFFilterServer,
)
from pmset.protocols.oprf_pir import (
    ComposableOPRFPIRProtocol,
    OPRFPIRClient,
    OPRFPIRServer,
    make_dh_oprf_paillier_pir,
    make_ecdh_oprf_paillier_2d_pir,
    make_ecdh_oprf_paillier_pir,
    make_oprf_rlwe_pir,
    make_rsa_oprf_paillier_pir,
)
from pmset.protocols.ot_gbf import (
    OTGarbledBloomClient,
    OTGarbledBloomFilterProtocol,
    OTGarbledBloomServer,
)

# Instantiate & register all canonical concrete protocols
DH_OPRF_PAILLIER_PIR = register_protocol(make_dh_oprf_paillier_pir())
ECDH_OPRF_PAILLIER_PIR = register_protocol(make_ecdh_oprf_paillier_pir())
ECDH_OPRF_PAILLIER_2D_PIR = register_protocol(make_ecdh_oprf_paillier_2d_pir())
RSA_OPRF_PAILLIER_PIR = register_protocol(make_rsa_oprf_paillier_pir())
OPRF_RLWE_PIR = register_protocol(make_oprf_rlwe_pir())
CUCKOO_OPRF_PIR = register_protocol(CuckooOPRFPIRProtocol())
FNP_PAILLIER = register_protocol(FNPPaillierProtocol())
ELGAMAL_EQUALITY = register_protocol(ElGamalEqualityProtocol())
ECDH_OPRF_FILTER = register_protocol(ECDHOPRFFilterProtocol())
OT_GARBLED_BLOOM = register_protocol(OTGarbledBloomFilterProtocol())
TWO_SERVER_DPF_PIR = register_protocol(TwoServerDPFPIRProtocol())
SHAMIR_MULTISERVER_PIR = register_protocol(ShamirMultiServerPIRProtocol())

__all__ = [
    "CUCKOO_OPRF_PIR",
    "ComposableOPRFPIRProtocol",
    "CuckooOPRFPIRClient",
    "CuckooOPRFPIRProtocol",
    "CuckooOPRFPIRServer",
    "DH_OPRF_PAILLIER_PIR",
    "ECDHOPRFFilterClient",
    "ECDHOPRFFilterProtocol",
    "ECDHOPRFFilterServer",
    "ECDH_OPRF_FILTER",
    "ECDH_OPRF_PAILLIER_2D_PIR",
    "ECDH_OPRF_PAILLIER_PIR",
    "ELGAMAL_EQUALITY",
    "ElGamalEqualityClient",
    "ElGamalEqualityProtocol",
    "ElGamalEqualityServer",
    "FNPPaillierClient",
    "FNPPaillierProtocol",
    "FNPPaillierServer",
    "FNP_PAILLIER",
    "MultiServerOPRFPIRClient",
    "MultiServerOPRFPIRServer",
    "OPRFPIRClient",
    "OPRFPIRServer",
    "OPRF_RLWE_PIR",
    "OTGarbledBloomClient",
    "OTGarbledBloomFilterProtocol",
    "OTGarbledBloomServer",
    "OT_GARBLED_BLOOM",
    "RSA_OPRF_PAILLIER_PIR",
    "SHAMIR_MULTISERVER_PIR",
    "ShamirMultiServerPIRProtocol",
    "TWO_SERVER_DPF_PIR",
    "TwoServerDPFPIRProtocol",
]
