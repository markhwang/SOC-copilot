"""
SOC Copilot - Slack Bot Integration

Provides a Slack interface for analysts to interact with SOC Copilot.
"""

import os
import json
import logging
import requests
from typing import Dict, Any, Optional

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk import WebClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_APP_TOKEN = os.getenv("SLACK_APP_TOKEN")
SOC_COPILOT_API_URL = os.getenv("SOC_COPILOT_API_URL", "http://localhost:8000")
ALERT_CHANNEL = os.getenv("SLACK_ALERT_CHANNEL", "#soc-alerts")

# Initialize Slack app
app = App(token=SLACK_BOT_TOKEN)
client = WebClient(token=SLACK_BOT_TOKEN)


# ============================================================================
# Message Formatting
# ============================================================================

def format_triage_message(triage_response: Dict[str, Any], alert_title: str) -> list:
    """Format triage response as Slack blocks."""
    
    # Risk score color
    risk_score = triage_response.get("risk_score", 5)
    if risk_score >= 8:
        risk_color = "🔴"
        risk_label = "Critical"
    elif risk_score >= 6:
        risk_color = "🟠"
        risk_label = "High"
    elif risk_score >= 4:
        risk_color = "🟡"
        risk_label = "Medium"
    else:
        risk_color = "🟢"
        risk_label = "Low"
    
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 Alert: {alert_title[:100]}",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Summary*\n{triage_response.get('summary', 'No summary available')}"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Risk Score*\n{risk_color} {risk_score}/10 ({risk_label})"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Alert ID*\n`{triage_response.get('alert_id', 'Unknown')}`"
                }
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Risk Reasoning*\n{triage_response.get('risk_reasoning', 'N/A')}"
            }
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Key Findings*\n" + "\n".join(
                    [f"• {finding}" for finding in triage_response.get("key_findings", ["No findings"])]
                )
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Recommended Investigation Steps*\n" + "\n".join(
                    [f"{i+1}. {step}" for i, step in enumerate(triage_response.get("investigation_steps", ["No steps"]))]
                )
            }
        }
    ]
    
    # Add MITRE context if available
    if triage_response.get("mitre_context"):
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*MITRE ATT&CK Context*\n{triage_response['mitre_context']}"
            }
        })
    
    # Add escalation warning if recommended
    if triage_response.get("escalation_recommended"):
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"⚠️ *Escalation Recommended*\n{triage_response.get('escalation_reason', 'See risk score')}"
            }
        })
    
    # Add action buttons
    blocks.extend([
        {"type": "divider"},
        {
            "type": "actions",
            "block_id": f"alert_actions_{triage_response.get('alert_id', 'unknown')}",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "🔍 Investigate", "emoji": True},
                    "style": "primary",
                    "action_id": "investigate_alert",
                    "value": triage_response.get("alert_id", "unknown")
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ Close as FP", "emoji": True},
                    "action_id": "close_false_positive",
                    "value": triage_response.get("alert_id", "unknown")
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "⬆️ Escalate", "emoji": True},
                    "style": "danger",
                    "action_id": "escalate_alert",
                    "value": triage_response.get("alert_id", "unknown")
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "📊 Show Queries", "emoji": True},
                    "action_id": "show_queries",
                    "value": triage_response.get("alert_id", "unknown")
                }
            ]
        }
    ])
    
    return blocks


def format_query_response(query_response: Dict[str, Any]) -> list:
    """Format query generation response as Slack blocks."""
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Query for:* {query_response.get('question', 'Unknown question')}"
            }
        }
    ]
    
    if query_response.get("kql_query"):
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*KQL (Sentinel)*\n```{query_response['kql_query']}```"
            }
        })
    
    if query_response.get("spl_query"):
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*SPL (Splunk)*\n```{query_response['spl_query']}```"
            }
        })
    
    if query_response.get("explanation"):
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Explanation*\n{query_response['explanation']}"
            }
        })
    
    if query_response.get("performance_notes"):
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"⚠️ {query_response['performance_notes']}"
                }
            ]
        })
    
    return blocks


# ============================================================================
# API Helpers
# ============================================================================

def call_soc_copilot_api(endpoint: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Call the SOC Copilot API."""
    try:
        response = requests.post(
            f"{SOC_COPILOT_API_URL}/api/v1/{endpoint}",
            json=data,
            timeout=60
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"API call failed: {e}")
        return None


# ============================================================================
# Slack Event Handlers
# ============================================================================

@app.event("app_mention")
def handle_mention(event, say):
    """Handle when the bot is mentioned."""
    text = event.get("text", "").lower()
    user = event.get("user")
    
    if "help" in text:
        say(
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*SOC Copilot Commands*\n\n"
                                "• `@SOC Copilot query <question>` - Generate KQL/SPL query\n"
                                "• `@SOC Copilot help` - Show this help message\n"
                                "• `/soc-query <question>` - Quick query generation\n\n"
                                "I also automatically triage alerts posted to this channel."
                    }
                }
            ]
        )
    elif "query" in text:
        # Extract the query question
        query_start = text.find("query") + 5
        question = text[query_start:].strip()
        
        if not question:
            say(f"<@{user}> Please provide a question after 'query'. Example: `@SOC Copilot query show failed logins for user@domain.com`")
            return
        
        say(f"<@{user}> Generating queries for: _{question}_")
        
        response = call_soc_copilot_api("query", {"question": question})
        
        if response:
            say(blocks=format_query_response(response))
        else:
            say(f"<@{user}> Sorry, I couldn't generate that query. Please try again.")
    else:
        say(f"<@{user}> I'm SOC Copilot! Say `@SOC Copilot help` to see what I can do.")


@app.command("/soc-query")
def handle_query_command(ack, command, respond):
    """Handle the /soc-query slash command."""
    ack()
    
    question = command.get("text", "").strip()
    
    if not question:
        respond("Please provide a question. Example: `/soc-query show failed logins in the last 24 hours`")
        return
    
    respond(f"Generating queries for: _{question}_")
    
    response = call_soc_copilot_api("query", {"question": question})
    
    if response:
        respond(blocks=format_query_response(response))
    else:
        respond("Sorry, I couldn't generate that query. Please try again.")


# ============================================================================
# Button Action Handlers
# ============================================================================

@app.action("investigate_alert")
def handle_investigate(ack, body, respond):
    """Handle the Investigate button click."""
    ack()
    alert_id = body["actions"][0]["value"]
    user = body["user"]["id"]
    
    respond(
        text=f"<@{user}> is investigating alert `{alert_id}`",
        response_type="in_channel"
    )
    
    # In production: Update alert status in SOAR/ticketing system
    logger.info(f"User {user} started investigating alert {alert_id}")


@app.action("close_false_positive")
def handle_close_fp(ack, body, respond):
    """Handle the Close as FP button click."""
    ack()
    alert_id = body["actions"][0]["value"]
    user = body["user"]["id"]
    
    # In production: Prompt for confirmation and reason
    respond(
        text=f"<@{user}> closed alert `{alert_id}` as False Positive",
        response_type="in_channel"
    )
    
    # Submit feedback
    call_soc_copilot_api("feedback", {
        "alert_id": alert_id,
        "triage_helpful": True,
        "rating": 4,
        "actual_disposition": "false_positive"
    })
    
    logger.info(f"User {user} closed alert {alert_id} as FP")


@app.action("escalate_alert")
def handle_escalate(ack, body, respond):
    """Handle the Escalate button click."""
    ack()
    alert_id = body["actions"][0]["value"]
    user = body["user"]["id"]
    
    respond(
        text=f"🚨 <@{user}> escalated alert `{alert_id}` to L2/L3",
        response_type="in_channel"
    )
    
    # In production: Create incident, page on-call, etc.
    logger.info(f"User {user} escalated alert {alert_id}")


@app.action("show_queries")
def handle_show_queries(ack, body, respond):
    """Handle the Show Queries button click."""
    ack()
    alert_id = body["actions"][0]["value"]
    
    # In production: Retrieve queries from cached triage response
    # For demo, generate a sample query
    respond(
        blocks=[
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Queries for Alert `{alert_id}`*"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*KQL (Sentinel)*\n```\n// Related activity for this alert\nSecurityEvent\n| where TimeGenerated > ago(24h)\n| where TargetUserName contains \"user\"\n| project TimeGenerated, Activity, TargetUserName, IpAddress\n| order by TimeGenerated desc\n```"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*SPL (Splunk)*\n```\nindex=wineventlog earliest=-24h\n| search user=\"*user*\"\n| table _time, signature, user, src_ip\n| sort -_time\n```"
                }
            }
        ]
    )


# ============================================================================
# Alert Ingestion (Webhook Handler)
# ============================================================================

def process_incoming_alert(alert_data: Dict[str, Any]) -> None:
    """Process an incoming alert and post triage to Slack."""
    
    # Call SOC Copilot API for triage
    triage_response = call_soc_copilot_api("triage", {"alert": alert_data})
    
    if not triage_response:
        logger.error(f"Failed to triage alert {alert_data.get('alert_id')}")
        return
    
    # Format and post to Slack
    blocks = format_triage_message(triage_response, alert_data.get("title", "Unknown Alert"))
    
    try:
        client.chat_postMessage(
            channel=ALERT_CHANNEL,
            blocks=blocks,
            text=f"New alert: {alert_data.get('title', 'Unknown')}"  # Fallback for notifications
        )
        logger.info(f"Posted triage for alert {alert_data.get('alert_id')} to Slack")
    except Exception as e:
        logger.error(f"Failed to post to Slack: {e}")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    logger.info("Starting SOC Copilot Slack Bot...")
    
    if not SLACK_BOT_TOKEN or not SLACK_APP_TOKEN:
        logger.error("SLACK_BOT_TOKEN and SLACK_APP_TOKEN must be set")
        exit(1)
    
    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    handler.start()
