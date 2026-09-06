import argparse
import concurrent.futures
import logging
import sys

from version import __version__

from aggregator.intel_aggregator import IntelAggregator
from analyzers.intel_analyzer import IntelAnalyzer
from clients.abuseipdb_client import AbuseIPDBClient
from clients.otx_client import OTXClient
from clients.threatfox_client import ThreatFoxClient
from models.ioc import IOC
from processors.abuseipdb_processor import AbuseIPDBProcessor
from processors.otx_processor import OTXProcessor
from processors.threatfox_processor import ThreatFoxProcessor
from renderers.assessment_renderer import AssessmentRenderer
from utils.data_loader import DataLoader
from utils.ioc_validator import IOCValidator
from utils.ssl_setup import initialize_ssl


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    )


def fetch_otx(ioc: IOC):
    client = OTXClient()
    processor = OTXProcessor()
    raw_data = DataLoader.load(
        client=client,
        ioc=ioc,
        output_file="outputs/otx_response.json"
    )
    if raw_data is None:
        return processor.create_failed_intel(ioc)
    return processor.process(raw_data, ioc)


def fetch_threatfox(ioc: IOC):
    client = ThreatFoxClient()
    processor = ThreatFoxProcessor()
    raw_data = DataLoader.load(
        client=client,
        ioc=ioc,
        output_file="outputs/threatfox_response.json"
    )
    if raw_data is None:
        return processor.create_failed_intel(ioc)
    return processor.process(raw_data, ioc)


def fetch_abuseipdb(ioc: IOC):
    if ioc.ioc_type not in ("IPv4", "IPv6"):
        logging.getLogger("ioc_insight").info(
            f"Skipping AbuseIPDB for non-IP IOC type: {ioc.ioc_type}"
        )
        return None
    client = AbuseIPDBClient()
    processor = AbuseIPDBProcessor()
    raw_data = DataLoader.load(
        client=client,
        ioc=ioc,
        output_file="outputs/abuseipdb_response.json"
    )
    if raw_data is None:
        return processor.create_failed_intel(ioc)
    return processor.process(raw_data, ioc)


def main():
    parser = argparse.ArgumentParser(
        description="IOC Insight - Threat Intelligence Assessment Tool"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"IOC Insight {__version__}"
    )
    parser.add_argument(
        "-i", "--ioc",
        type=str,
        required=True,
        help="IOC value to assess (e.g. IP, domain, hash, URL)"
    )
    parser.add_argument(
        "-t", "--type",
        type=str,
        required=True,
        help="IOC type (IPv4, IPv6, domain, hash, url)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging"
    )
    

    args = parser.parse_args()
    setup_logging(args.verbose)

    initialize_ssl()

    ioc_value, ioc_type = IOCValidator.validate_and_normalize(args.ioc, args.type)

    if ioc_type == "unknown":
        print(
            f"Error: Unable to determine IOC type for value '{args.ioc}'. Please specify --type.",
            file=sys.stderr
        )
        sys.exit(1)

    ioc = IOC(
        ioc_type=ioc_type,
        ioc_value=ioc_value
    )

    intel_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(fetch_otx, ioc),
            executor.submit(fetch_threatfox, ioc),
            executor.submit(fetch_abuseipdb, ioc)
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                if res is not None:
                    intel_results.append(res)
            except Exception as e:
                logging.getLogger("ioc_insight").error(f"Provider lookup task failed: {e}")

    if not intel_results:
        print(f"No intelligence collected for {ioc.ioc_value}.", file=sys.stderr)
        sys.exit(1)

    aggregator = IntelAggregator()
    consolidated_intel = aggregator.aggregate(intel_results)

    analyzer = IntelAnalyzer()
    assessment = analyzer.analyze(consolidated_intel)

    renderer = AssessmentRenderer()
    renderer.render(assessment)


if __name__ == "__main__":
    main()
