import asyncio
import uuid
import json
import os
from pathlib import Path
import shutil
import re
from typing import List, Dict, Any, Tuple

from langgraph.store.memory import InMemoryStore
from langchain.embeddings import init_embeddings
from langchain_community.embeddings import HuggingFaceEmbeddings
from dotenv import load_dotenv

from multi_agent.main_agent.graph import build_graph
from multi_agent.common.global_state import State_global


load_dotenv()
EXECUTION = os.getenv("EXECUTION_MODE", "API")

BASE_DIR = Path(__file__).resolve().parent
RESULTS_BASE_DIR = BASE_DIR.parent / "results"
RESULTS_BASE_DIR.mkdir(parents=True, exist_ok=True)

DATASET_DIR = BASE_DIR.parent / "data" / "tls_termination_events"
RAW_DIR = DATASET_DIR / "traffic_exercises"
GROUNDTRUTH_FILE = RAW_DIR / "GT.json"


def get_number_of_executions(default: int = 3) -> int:
    raw = os.getenv("NUMBER_OF_EXECUTIONS", str(default))
    try:
        value = int(raw)
        if value < 1:
            raise ValueError("NUMBER_OF_EXECUTIONS must be >= 1")
        return value
    except ValueError:
        print(f"[WARN] Invalid NUMBER_OF_EXECUTIONS='{raw}', falling back to {default}")
        return default


NUMBER_OF_EXECUTIONS = get_number_of_executions()

NOT_GIVEN_ANSWER = """
{
  "executive_summary": "No analysis or output was produced by the agent.",
  "victim_details": {
    "victim_host_name": null,
    "victim_ip_address": null,
    "victim_mac_address": null,
    "victim_windows_user_account_name": null
  }
}
"""


def load_data() -> List[Tuple[str, Dict[str, Any]]]:
    with open(GROUNDTRUTH_FILE, "r") as file:
        data = json.load(file)
    return list(data.items())


def init_store() -> InMemoryStore:
    if EXECUTION == "LOCAL":
        return InMemoryStore(
            index={
                "embed": HuggingFaceEmbeddings(model_name="BAAI/bge-small-en"),
                "dims": 384,
            }
        )
    else:
        return InMemoryStore(
            index={
                "embed": init_embeddings("openai:text-embedding-3-small"),
                "dims": 1536,
            }
        )


def get_artifact_paths(event_id: str) -> dict:
    event_dir = RAW_DIR / event_id
    pcap_files = list(event_dir.glob("*.pcap"))
    if not pcap_files:
        raise FileNotFoundError(f"No .pcap found in {event_dir}")
    return {
        "log_dir": str(event_dir),
        "pcap_path": str(pcap_files[0]),
    }


def _normalize_for_match(s: str | None) -> str:
    """Lowercase, strip, e rimuove separatori comuni per hostname/IP/MAC per un confronto robusto."""
    if not s:
        return ""
    s = str(s).strip().lower()
    return re.sub(r"[\s:_\-\.\(\)\[\]]+", "", s)


def _coalesce(*vals):
    for v in vals:
        if v is not None and str(v).strip():
            return v
    return None


def parse_agent_output(answer_str: str) -> dict:
    # 1) Prova a leggere JSON "ben formato"
    try:
        obj = json.loads(answer_str)
        summary = _coalesce(obj.get("executive_summary"), obj.get("summary"), obj.get("report"), "")
        vd = obj.get("victim_details") or {}
        return {
            "executive_summary": summary or "No summary provided.",
            "victim_details": {
                "victim_host_name": _coalesce(vd.get("victim_host_name"), vd.get("hostname")),
                "victim_ip_address": _coalesce(vd.get("victim_ip_address"), vd.get("ip_address"), vd.get("ip")),
                "victim_mac_address": _coalesce(vd.get("victim_mac_address"), vd.get("mac_address"), vd.get("mac")),
                "victim_windows_user_account_name": _coalesce(vd.get("victim_windows_user_account_name"), vd.get("windows_user"), vd.get("user")),
            },
        }
    except Exception:
        pass

    # 2) Fallback: regex su testo libero
    patterns_primary = {
        "victim_host_name": r"(?im)^\s*(?:Hostname|Host\s*name)\s*:\s*([A-Za-z0-9_.\-]+)\s*$",
        "victim_ip_address": r"(?im)^\s*(?:IP\s*Address|IP)\s*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*$",
        "victim_mac_address": r"(?im)^\s*(?:MAC\s*Address|MAC)\s*:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s*$",
        "victim_windows_user_account_name": r"(?im)^\s*(?:Windows\s*User(?:\s*Account\s*Name)?|User)\s*:\s*([A-Za-z0-9_.\-]+)\s*$",
    }

    victim = {k: None for k in patterns_primary.keys()}
    for key, pat in patterns_primary.items():
        m = re.search(pat, answer_str)
        if m:
            victim[key] = m.group(1).strip()

    if not victim["victim_host_name"]:
        m = re.search(r"(?i)victim\s*host\s*:\s*([A-Za-z0-9_.\-]+)", answer_str)
        if m:
            victim["victim_host_name"] = m.group(1).strip()
    if not victim["victim_host_name"]:
        m = re.search(r"(?i)\b([A-Z0-9][A-Z0-9_.\-]{2,})\b.*?\(\s*(?:internal\s+)?ip\s*[:=]\s*[0-9]{1,3}(?:\.[0-9]{1,3}){3}", answer_str)
        if m:
            victim["victim_host_name"] = m.group(1).strip()

    if not victim["victim_ip_address"]:
        m = re.search(r"(?i)(?:internal\s+ip|ip)\s*[:=]\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", answer_str)
        if m:
            victim["victim_ip_address"] = m.group(1).strip()

    if not victim["victim_mac_address"]:
        m = re.search(r"(?i)\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b", answer_str)
        if m:
            victim["victim_mac_address"] = m.group(1).strip()

    if not victim["victim_windows_user_account_name"]:
        m = re.search(r"(?i)(?:user|account|logg(?:ed|on)[-\s]*user)\s*[:=]\s*([A-Za-z0-9_.\-]+)", answer_str)
        if m:
            victim["victim_windows_user_account_name"] = m.group(1).strip()
    if not victim["victim_windows_user_account_name"]:
        m = re.search(r"(?i)\b([a-z][a-z0-9_.\-]{2,})@(?:[A-Za-z0-9_.\-]+\.)?[A-Za-z]{2,}\b", answer_str)
        if m:
            victim["victim_windows_user_account_name"] = m.group(1).strip()

    m_sum = re.search(r"(?is)FINAL\s+REPORT:\s*(.+?)(?:\n{2,}|VICTIM\s*DETAILS\s*:|$)", answer_str)
    if m_sum:
        summary = m_sum.group(1).strip()
    else:
        lines = [ln.strip() for ln in answer_str.strip().splitlines() if ln.strip()]
        summary = "\n".join(lines[:6]) if lines else "No summary provided."

    for k, v in victim.items():
        if isinstance(v, str) and _normalize_for_match(v) in {"notfound", "none", "null"}:
            victim[k] = None

    return {
        "executive_summary": summary or "No summary provided.",
        "victim_details": victim,
    }


def check_correctness(answers: List[str | None], expected_answer: List[str | None]) -> List[bool]:
    """
    Regole:
    - Se expected è vuoto: corretto solo se anche answer è vuoto o esplicitamente "notfound"/"none"/"null".
    - Se expected è presente: answer vuoto NON è corretto.
    - Confronto: exact match oppure (tolleranza substring in entrambe le direzioni).
    """
    results = []
    for ans_raw, exp_raw in zip(answers, expected_answer):
        ans = _normalize_for_match(ans_raw)
        exp = _normalize_for_match(exp_raw)

        # expected mancante
        if not exp:
            results.append(ans in {"", "notfound", "none", "null"})
            continue

        # expected presente -> answer mancante è sbagliato
        if not ans or ans in {"notfound", "none", "null"}:
            results.append(False)
            continue

        # match (exact o substring bidirezionale)
        is_correct = (ans == exp) or (exp in ans) or (ans in exp)
        results.append(is_correct)

    return results


async def run_forensic_example(
    graph,
    execution_number: int,
    event_id: str,
    pcap_path: str,
    log_dir: str,
    max_steps: int = 25,
    strategy: str = "LLM_summary",
):
    state = State_global(
        pcap_path=pcap_path,
        log_dir=log_dir,
        messages=[],
        steps=max_steps,
        event_id=event_id,
        strategy=strategy,
    )
    thread_id = str(uuid.uuid4())
    state = await graph.ainvoke(
        state,
        config={
            "configurable": {"thread_id": thread_id},
            "recursion_limit": 100,
        },
    )

    answer = state["messages"][-1]
    done = state.get("done", False)
    steps_remaining = state.get("steps", None)
    in_tokens = state.get("inputTokens", None)
    out_tokens = state.get("outputTokens", None)

    steps_dir = RESULTS_BASE_DIR / f"run{execution_number}" / "log_steps"
    steps_dir.mkdir(parents=True, exist_ok=True)
    steps_path = steps_dir / f"steps_{event_id}.txt"
    with steps_path.open("w", encoding="utf-8") as f:
        f.write(f"[Task {event_id}]\n")
        for i, message in enumerate(state["messages"]):
            f.write(f"Step {i+1}:\n{message.content}\n\n")

    return (
        done,
        str(answer.content),
        steps_remaining,
        in_tokens,
        out_tokens,
        max_steps,
    )


async def main():
    if RESULTS_BASE_DIR.exists() and RESULTS_BASE_DIR.is_dir():
        shutil.rmtree(RESULTS_BASE_DIR)
    RESULTS_BASE_DIR.mkdir(parents=True, exist_ok=True)

    pcaps = load_data()

    for execution_number in range(1, NUMBER_OF_EXECUTIONS + 1):
        run_dir = RESULTS_BASE_DIR / f"run{execution_number}"
        run_dir.mkdir(parents=True, exist_ok=True)
        result_file = run_dir / "result.txt"

        counters = [0] * 4  # host, ip, mac, user

        with result_file.open("w", encoding="utf-8") as f:
            f.write(f"=== Forensic Evaluation Run {execution_number} ===\n\n")
            for event_id, game in pcaps:
                paths = get_artifact_paths(event_id)
                store = init_store()
                graph = build_graph(store)

                expected_answer = [
                    game.get("Victim_Host_Name"),
                    game.get("Victim_IP_Address"),
                    game.get("Victim_MAC_Address"),
                    game.get("Victim_Windows_User_Account_Name"),
                ]

                done, answer_str, steps_remaining, inTokens, outTokens, max_steps = await run_forensic_example(
                    graph=graph,
                    execution_number=execution_number,
                    event_id=event_id,
                    pcap_path=paths["pcap_path"],
                    log_dir=paths["log_dir"],
                )

                if done:
                    parsed_answer = parse_agent_output(answer_str)
                else:
                    parsed_answer = json.loads(NOT_GIVEN_ANSWER)

                summary = parsed_answer.get("executive_summary", "No summary provided.")
                victim_details = parsed_answer.get("victim_details", {})

                answers = [
                    victim_details.get("victim_host_name"),
                    victim_details.get("victim_ip_address"),
                    victim_details.get("victim_mac_address"),
                    victim_details.get("victim_windows_user_account_name"),
                ]

                f.write(f"[Task {event_id}]\n")
                f.write("-" * 80 + "\n")
                f.write("Executive Summary:\n")
                f.write(summary.strip() + "\n\n")

                f.write("Victim Details (Agent):\n")
                f.write(f"  Hostname     : {answers[0]}\n")
                f.write(f"  IP Address   : {answers[1]}\n")
                f.write(f"  MAC Address  : {answers[2]}\n")
                f.write(f"  Windows User : {answers[3]}\n\n")

                f.write("Ground Truth:\n")
                f.write(f"  Hostname     : {expected_answer[0]}\n")
                f.write(f"  IP Address   : {expected_answer[1]}\n")
                f.write(f"  MAC Address  : {expected_answer[2]}\n")
                f.write(f"  Windows User : {expected_answer[3]}\n\n")

                steps_used = None
                if isinstance(steps_remaining, int):
                    steps_used = max(0, max_steps - steps_remaining)
                f.write("Run Metadata:\n")
                f.write(f"  Steps used   : {steps_used}\n")
                f.write(f"  Steps remain : {steps_remaining}\n")
                f.write(f"  Input tokens : {inTokens}\n")
                f.write(f"  Output tokens: {outTokens}\n")
                f.write("-" * 80 + "\n\n")

                correct = check_correctness(answers, expected_answer)
                for j, is_correct in enumerate(correct):
                    if is_correct:
                        counters[j] += 1

                

            total = len(pcaps) if len(pcaps) > 0 else 1  # richiesto mantenere len(pcaps)
            f.write("\n=== Final Statistics ===\n")
            f.write(f"Accuracy Victim Hostname     : {counters[0]/total*100:.2f}% ({counters[0]}/{total})\n")
            f.write(f"Accuracy Victim IP Address   : {counters[1]/total*100:.2f}% ({counters[1]}/{total})\n")
            f.write(f"Accuracy Victim MAC Address  : {counters[2]/total*100:.2f}% ({counters[2]}/{total})\n")
            f.write(f"Accuracy Victim Windows User : {counters[3]/total*100:.2f}% ({counters[3]}/{total})\n")
            f.write("Finished running selected tasks.\n")


if __name__ == "__main__":
    asyncio.run(main())
