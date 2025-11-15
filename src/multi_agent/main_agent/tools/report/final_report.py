from pydantic import BaseModel
from langchain_core.tools import Tool


class FinalAnswerArgs(BaseModel):
    executive_summary: str
    victim_hostname: str
    victim_ip: str
    victim_mac: str
    victim_windows_user_account_name: str


def finalAnswerFormatter_func(executive_summary: str, victim_hostname: str, victim_ip: str, victim_mac: str, victim_windows_user_account_name: str) -> str:
    """Format the final answer."""
    final_report = f"\nFINAL REPORT:\n"
    final_report += executive_summary
    final_report += f"\nVICTIM DETAILS:\n"
    final_report += f"Hostname: {victim_hostname}\n"
    final_report += f"IP Address: {victim_ip}\n"
    final_report += f"MAC Address: {victim_mac}\n"
    final_report += f"Windows User Account Name: {victim_windows_user_account_name}\n"
    return final_report


finalAnswerFormatter = Tool(
    name="final_answer_formatter",
    description="""Use this tool to provide the final, complete, structured report for the investigation. 
        executive_summary: A clear summary describing what happened, when, and who was involved. This summary must also include a description 
        of the key Indicators of Compromise (IOCs).In this context, IOCs are the specific, actionable forensic artifacts you extracted from the 
        network traffic (like malicious domains, C2 IP addresses, suspicious URLs, or file hashes) that prove the compromise occurred.
        victim_hostname: The victim's hostname identified from the traffic;
        victim_ip: The victim's internal IP address;
        victim_mac: The victim's MAC address;
        victim_windows_user_account_name: The victim's Windows username.
    """,
    args_schema=FinalAnswerArgs,
    func=finalAnswerFormatter_func,
)

__all__ = ["finalAnswerFormatter", "finalAnswerFormatter_func"]
