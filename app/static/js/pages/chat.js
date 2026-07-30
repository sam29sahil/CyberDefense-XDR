/* ==========================================================================
   chat.js — page module for app/chat.html
   Depends on: AI_CONVERSATIONS_DATA, SUGGESTED_QUESTIONS, CANNED_RESPONSES,
   DEFAULT_RESPONSE (data/ai-data.js)
   ========================================================================== */

   (function () {
    let conversations = AI_CONVERSATIONS_DATA.map((c) => ({ ...c, messages: c.messages.map((m) => ({ ...m })) }));
    let activeId = conversations[0]?.id;
  
    function renderSidebar() {
      document.getElementById("chatSidebar").innerHTML = conversations
        .slice().sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
        .map((c) => `
          <div class="chat-sidebar-item ${c.id === activeId ? "active" : ""}" data-id="${c.id}">
            <div class="cs-title">${XDRUtils.escapeHtml(c.title)}</div>
            <div class="cs-time">${XDRUtils.formatTime(c.updatedAt)}</div>
          </div>`).join("");
      document.querySelectorAll(".chat-sidebar-item").forEach((el) => el.addEventListener("click", () => {
        activeId = el.dataset.id;
        renderSidebar();
        renderMessages();
      }));
    }
  
    function bubbleHtml(msg) {
      const isUser = msg.role === "user";
      return `
        <div class="chat-bubble-row ${isUser ? "user" : "assistant"}">
          <span class="chat-avatar ${isUser ? "user" : "assistant"}"><i class="bi ${isUser ? "bi-person" : "bi-stars"}"></i></span>
          <div class="chat-bubble">${XDRUtils.escapeHtml(msg.text)}</div>
        </div>`;
    }
  
    function renderMessages() {
      const conv = conversations.find((c) => c.id === activeId);
      const el = document.getElementById("chatMessages");
      el.innerHTML = conv ? conv.messages.map(bubbleHtml).join("") : "";
      el.scrollTop = el.scrollHeight;
    }
  
    function renderSuggestions() {
      document.getElementById("chatSuggestions").innerHTML = SUGGESTED_QUESTIONS.map((q) => `<span class="chat-suggestion-chip">${q}</span>`).join("");
      document.querySelectorAll(".chat-suggestion-chip").forEach((chip) => chip.addEventListener("click", () => sendMessage(chip.textContent)));
    }
  
    function findResponse(text) {
      const lower = text.toLowerCase();
      const hit = CANNED_RESPONSES.find((r) => r.match.some((m) => lower.includes(m)));
      return hit ? hit.text : DEFAULT_RESPONSE;
    }
  
    function sendMessage(text) {
      text = text.trim();
      if (!text) return;
      let conv = conversations.find((c) => c.id === activeId);
      if (!conv) return;
      conv.messages.push({ role: "user", text, ts: new Date().toISOString() });
      conv.updatedAt = new Date().toISOString();
      renderMessages();
      renderSidebar();
      document.getElementById("chatInput").value = "";
  
      // typing indicator
      const el = document.getElementById("chatMessages");
      el.insertAdjacentHTML("beforeend", `<div class="chat-bubble-row assistant" id="typingRow"><span class="chat-avatar assistant"><i class="bi bi-stars"></i></span><div class="chat-bubble typing-dots"><span></span><span></span><span></span></div></div>`);
      el.scrollTop = el.scrollHeight;
  
      setTimeout(() => {
        document.getElementById("typingRow")?.remove();
        conv.messages.push({ role: "assistant", text: findResponse(text), ts: new Date().toISOString() });
        renderMessages();
      }, 900);
    }
  
    document.getElementById("chatSendBtn").addEventListener("click", () => sendMessage(document.getElementById("chatInput").value));
    document.getElementById("chatInput").addEventListener("keydown", (e) => { if (e.key === "Enter") sendMessage(e.target.value); });
  
    document.getElementById("newChatBtn").addEventListener("click", () => {
      const newConv = { id: `CONV-${Math.floor(Math.random() * 9000 + 1000)}`, title: "New conversation", updatedAt: new Date().toISOString(), messages: [] };
      conversations.unshift(newConv);
      activeId = newConv.id;
      renderSidebar();
      renderMessages();
    });
  
    renderSidebar();
    renderMessages();
    renderSuggestions();
  
    // Prefill from ?q= (used by dashboard suggestion chips)
    const params = new URLSearchParams(window.location.search);
    const prefill = params.get("q");
    if (prefill) sendMessage(prefill);
  })();
  