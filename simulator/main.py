import argparse
import json
import sys
import time

from simulator.scenarios import ScenarioEngine


def main():
    parser = argparse.ArgumentParser(description="Security Event Simulator CLI")
    parser.add_argument("--rate", type=float, default=2.0, help="Baseline event generation rate (events/second)")
    parser.add_argument("--duration", type=int, default=10, help="Duration to run simulator in seconds (0 for infinite)")
    parser.add_argument(
        "--scenario",
        type=str,
        default="none",
        choices=["none", "bruteforce", "portscan", "suspicious_login", "http_anomaly", "all"],
        help="Attack scenario to inject",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="console",
        choices=["console", "file"],
        help="Output sink destination",
    )
    parser.add_argument("--out-file", type=str, default="events.json", help="File path if output mode is file")

    args = parser.parse_args()

    start_time = time.time()
    events_generated = 0

    out_handle = open(args.out_file, "a") if args.output == "file" else sys.stdout

    try:
        # Inject scenario at start if specified
        scenario_events = []
        if args.scenario == "bruteforce" or args.scenario == "all":
            scenario_events.extend(ScenarioEngine.generate_bruteforce_scenario())
        if args.scenario == "portscan" or args.scenario == "all":
            scenario_events.extend(ScenarioEngine.generate_portscan_scenario())
        if args.scenario == "suspicious_login" or args.scenario == "all":
            scenario_events.extend(ScenarioEngine.generate_suspicious_login_scenario())
        if args.scenario == "http_anomaly" or args.scenario == "all":
            scenario_events.extend(ScenarioEngine.generate_http_anomaly_scenario())

        for event in scenario_events:
            out_handle.write(event.model_dump_json() + "\n")
            out_handle.flush()
            events_generated += 1

        # Continuous normal event generation loop
        delay = 1.0 / args.rate if args.rate > 0 else 0.5
        while True:
            elapsed = time.time() - start_time
            if args.duration > 0 and elapsed >= args.duration:
                break

            event = ScenarioEngine.generate_random_normal_event()
            out_handle.write(event.model_dump_json() + "\n")
            out_handle.flush()
            events_generated += 1

            time.sleep(delay)

    except KeyboardInterrupt:
        pass
    finally:
        if args.output == "file":
            out_handle.close()
        print(f"\nSimulator finished. Total events generated: {events_generated}", file=sys.stderr)


if __name__ == "__main__":
    main()
