"""
CyberDefense XDR
AI Security Assistant Routes
"""

import uuid
import json
from flask import render_template, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.ai_assistant import ai_assistant
from app.ai_assistant.models import AIConversation, AIMessage
from app.ai_assistant.security import sanitize_user_input
from app.ai_assistant.context import gather_security_context
from app.ai_assistant.provider import get_ai_provider, get_ai_status


@ai_assistant.route("/")
@login_required
def chat_page():
    return render_template("ai_assistant/chat.html")


@ai_assistant.route("/api/status", methods=["GET"])
@login_required
def api_status():
    return jsonify(get_ai_status())


@ai_assistant.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    payload = request.get_json() or {}
    raw_prompt = (payload.get("prompt") or "").strip()
    conv_id = (payload.get("conversation_id") or "").strip()
    entity_type = payload.get("entity_type")
    entity_id = payload.get("entity_id")

    if not raw_prompt:
        return jsonify({"status": "error", "message": "Prompt cannot be empty"}), 400

    prompt = sanitize_user_input(raw_prompt)

    # Resolve or create conversation
    conv = None
    if conv_id:
        conv = AIConversation.query.filter_by(conversation_id=conv_id).first()

    if not conv:
        new_id = str(uuid.uuid4())
        # First 50 chars of prompt as title
        title = prompt[:50] + ("..." if len(prompt) > 50 else "")
        conv = AIConversation(
            conversation_id=new_id,
            title=title,
            user_id=getattr(current_user, "id", None),
            entity_type=entity_type,
            entity_id=entity_id,
        )
        db.session.add(conv)
        db.session.commit()

    # Load history
    history_messages = conv.messages.all()
    history_list = [{"role": m.role, "content": m.content} for m in history_messages[-6:]]

    # Gather real context
    ctx = gather_security_context(prompt)

    # Persist user message
    user_msg = AIMessage(
        conversation_id=conv.id,
        role="user",
        content=prompt,
        evidence_json=json.dumps(ctx["evidence"]),
    )
    db.session.add(user_msg)
    db.session.commit()

    # Generate response
    provider = get_ai_provider()
    res = provider.generate_response(prompt, ctx["wrapped_context"], history=history_list)

    # Persist assistant response
    assistant_msg = AIMessage(
        conversation_id=conv.id,
        role="assistant",
        content=res["content"],
        evidence_json=json.dumps(ctx["evidence"]),
        analysis_json=json.dumps(res.get("analysis", {})),
        recommendations_json=json.dumps(res.get("recommendations", [])),
        risk_level=res.get("risk_level", "INFORMATIONAL"),
        tokens_used=res.get("tokens_used", 0),
    )
    db.session.add(assistant_msg)
    db.session.commit()

    return jsonify({
        "status": "success",
        "conversation_id": conv.conversation_id,
        "message": assistant_msg.to_dict(),
        "provider": res.get("provider", "AI Assistant"),
    })


@ai_assistant.route("/api/history", methods=["GET"])
@login_required
def api_history():
    query = AIConversation.query
    if getattr(current_user, "id", None):
        query = query.filter(
            (AIConversation.user_id == current_user.id) | (AIConversation.user_id.is_(None))
        )
    conversations = query.order_by(AIConversation.updated_at.desc()).limit(20).all()
    return jsonify({
        "status": "success",
        "conversations": [c.to_dict() for c in conversations]
    })


@ai_assistant.route("/api/conversations/<conversation_id>", methods=["GET"])
@login_required
def api_get_conversation(conversation_id):
    conv = AIConversation.query.filter_by(conversation_id=conversation_id).first_or_404()
    # IDOR Defense: only allow owner or admin
    if conv.user_id and getattr(current_user, "id", None) and conv.user_id != current_user.id:
        if getattr(current_user, "role", "") != "admin":
            return jsonify({
                "status": "error",
                "message": "Access denied. You do not have permission to view this conversation."
            }), 403

    return jsonify({
        "status": "success",
        "conversation": conv.to_dict(include_messages=True)
    })


@ai_assistant.route("/api/conversations/<conversation_id>", methods=["DELETE"])
@login_required
def api_delete_conversation(conversation_id):
    conv = AIConversation.query.filter_by(conversation_id=conversation_id).first_or_404()
    # IDOR Defense: only allow owner or admin
    if conv.user_id and getattr(current_user, "id", None) and conv.user_id != current_user.id:
        if getattr(current_user, "role", "") != "admin":
            return jsonify({
                "status": "error",
                "message": "Access denied. You do not have permission to delete this conversation."
            }), 403

    db.session.delete(conv)
    db.session.commit()
    return jsonify({
        "status": "success",
        "message": "Conversation deleted"
    })

