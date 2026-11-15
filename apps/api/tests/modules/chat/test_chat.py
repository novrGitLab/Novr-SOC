"""NovrChat: answers cite only the active organization's records; tools obey permissions; action requests are refused;
report generation needs reports:manage; conversations are private to their user; every exchange is audited."""
from tests.conftest import audit_actions


def _ask(c, q):
    conv = c.post("/api/v1/chat/conversations", {}).json()
    r = c.post(f"/api/v1/chat/conversations/{conv['id']}/messages", {"content": q})
    assert r.status_code == 201, r.text
    return conv, r.json()["answer"]


def test_answers_cite_only_the_organizations_records(as_user, fixture_alerts, world, owner):
    a, b = as_user("analyst_a"), as_user("analyst_b")
    _, ans = _ask(a, "What critical and high alerts came in this month?")
    assert ans["state"] == "complete" and any(t["tool"] == "alerts" and t["state"] == "ok" for t in ans["tools"])
    alpha_ids = {x["id"] for x in a.get("/api/v1/soc/alerts?limit=200").json()["items"]}
    beta_ids = {x["id"] for x in b.get("/api/v1/soc/alerts?limit=200").json()["items"]}
    cited = {c["ref"]["id"] for c in ans["citations"] if c["ref"]["type"] == "alert"}
    assert cited and cited <= alpha_ids and not (cited & beta_ids)
    assert all(f"[{c['citation_id']}]" in ans["content"] for c in ans["citations"])
    _, bans = _ask(b, "What critical and high alerts came in this month?")
    assert not ({c["ref"]["id"] for c in bans["citations"]} & alpha_ids)
    assert {"CHAT_MESSAGE"} <= {e["action"] for e in audit_actions(owner, org=world.alpha)}


def test_permissions_refusals_and_reports(as_user, fixture_alerts, world):
    e = as_user("exec_a")
    _, ans = _ask(e, "How many open cases and incidents do we have?")
    assert any(t["tool"] == "cases" and t["state"] == "not_permitted" for t in ans["tools"]) and ans["citations"] == []
    _, ref = _ask(as_user("analyst_a"), "Block 203.0.113.45 on the firewall now")
    assert ref["state"] == "refused" and "read-only" in ref["content"] and ref["citations"] == []
    acts = as_user("analyst_a").get("/api/v1/soar/ai-activity?kind=chat_refused").json()["items"]
    assert acts and acts[0]["outcome"] == "refused"
    _, rep = _ask(as_user("analyst_a"), "Generate an executive report")
    tool = next(t for t in rep["tools"] if t["tool"] == "generate_report")
    assert tool["state"] == "ok" and rep["citations"][0]["ref"]["type"] == "report"
    rid = rep["citations"][0]["ref"]["id"]
    assert as_user("analyst_a").get(f"/api/v1/reports/{rid}").json()["type"] == "executive"
    _, nope = _ask(e, "Generate an executive report")
    assert next(t for t in nope["tools"] if t["tool"] == "generate_report")["state"] == "not_permitted"
    _, help_ = _ask(e, "hello")
    assert "I can answer" in help_["content"]
    assert as_user("portal_a").get("/api/v1/chat/conversations").status_code == 403


def test_conversations_are_private_to_their_user(as_user):
    conv, _ = _ask(as_user("analyst_a"), "What is our security posture?")
    assert as_user("exec_a").get(f"/api/v1/chat/conversations/{conv['id']}").status_code == 404      # same org, other user
    assert as_user("analyst_a").get(f"/api/v1/chat/conversations/{conv['id']}").json()["messages"][1]["role"] == "assistant"
    assert as_user("analyst_a").delete(f"/api/v1/chat/conversations/{conv['id']}").status_code == 204


def test_nhai_drafts_prose_over_the_same_citations(fixture_settings, fixture_alerts, app_engine):
    """With NHAI configured, the answer carries a chat_answer job built from the retrieved citations only."""
    from app.connectors.inference import TestInferenceAdapter
    from app.main import create_app
    from tests.modules.conftest import Client
    from tests.modules.nhai.test_nhai import drain
    app = create_app(fixture_settings.model_copy(update={"nhai_backend": "test_adapter"}))
    a = Client(app, "analyst_a")
    conv = a.post("/api/v1/chat/conversations", {}).json()
    r = a.post(f"/api/v1/chat/conversations/{conv['id']}/messages", {"content": "Which critical and high alerts came in this month?"})
    assert r.status_code == 201, r.text
    ans = r.json()["answer"]
    assert ans["citations"] and ans["nhai"] and ans["nhai"]["task"] == "chat_answer"
    assert "succeeded" in drain(app_engine, fixture_settings, TestInferenceAdapter())
    again = a.get(f"/api/v1/chat/conversations/{conv['id']}").json()["messages"][1]["nhai"]
    assert again["status"] == "succeeded" and again["result"]["status"] == "draft"
    cited = {c["ref"]["id"] for c in again["result"]["citations"]}
    assert cited <= {c["ref"]["id"] for c in ans["citations"]} | {ans["id"]}
