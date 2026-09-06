import json
import logging
import os

from config.config import DEVELOPMENT_MODE

logger = logging.getLogger("ioc_insight")


class DataLoader:

    @staticmethod
    def load(client, ioc, output_file):
        if DEVELOPMENT_MODE:
            if os.path.exists(output_file):
                try:
                    with open(
                        output_file,
                        "r",
                        encoding="utf-8"
                    ) as file:
                        return json.load(file)
                except Exception as e:
                    logger.warning(
                        f"Failed to read development output file {output_file}: {e}"
                    )
            logger.warning(
                f"Development file {output_file} not found. Querying provider API."
            )

        try:
            raw_data = client.lookup(ioc)
        except Exception as e:
            logger.error(f"Error during client lookup: {e}")
            return None

        if DEVELOPMENT_MODE and raw_data:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            try:
                with open(
                    output_file,
                    "w",
                    encoding="utf-8"
                ) as file:
                    json.dump(raw_data, file, indent=4)
            except Exception as e:
                logger.warning(f"Could not save development response: {e}")

        return raw_data or {}
