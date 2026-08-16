"""
Logging Configuration
"""

import logging


def configure_logger():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s"
    )

    return logging.getLogger("CyberDefense-XDR")
