/**
 * AI Security Assistant Client Controller
 */
document.addEventListener('DOMContentLoaded', () => {
  let currentConversationId = null;

  const chatMessages = document.getElementById('chatMessages');
  const chatForm = document.getElementById('chatForm');
  const chatInput = document.getElementById('chatInput');
  const btnSendMessage = document.getElementById('btnSendMessage');
  const sendIcon = document.getElementById('sendIcon');
  const conversationsList = document.getElementById('conversationsList');
  const btnNewChat = document.getElementById('btnNewChat');
  const aiProviderBadge = document.getElementById('aiProviderBadge');

  // Load Status
  function loadStatus() {
    fetch('/ai-assistant/api/status')
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success' && aiProviderBadge) {
          if (data.configured) {
            let modelLabel = data.model || '';
            if (modelLabel.toLowerCase() === 'gemini-2.5-flash') {
              modelLabel = '2.5 Flash';
            }
            aiProviderBadge.textContent = `${data.provider} ${modelLabel} • ${data.mode || 'ADVISORY ONLY'}`.trim();
          } else {
            aiProviderBadge.textContent = `${data.provider} [FALLBACK / ${data.mode || 'ADVISORY ONLY'}]`;
          }
        }
      })
      .catch(err => console.error('Failed to load AI status:', err));
  }

  // Load History
  function loadHistory() {
    fetch('/ai-assistant/api/history')
      .then(res => res.json())
      .then(data => {
        if (!conversationsList) return;
        if (!data.conversations || data.conversations.length === 0) {
          conversationsList.innerHTML = '<div class="text-muted text-center py-3">No previous sessions</div>';
          return;
        }
        conversationsList.innerHTML = data.conversations.map(c => `
          <div class="conv-item ${c.conversation_id === currentConversationId ? 'active' : ''}" data-id="${c.conversation_id}">
            <div class="d-flex justify-content-between align-items-center">
              <span class="text-light text-truncate fw-semibold" style="max-width: 170px;">
                ${escapeHtml(c.title)}
              </span>
              <button class="btn btn-link text-muted p-0 btn-del-conv" data-id="${c.conversation_id}" title="Delete session">
                <i class="bi bi-trash small"></i>
              </button>
            </div>
            <div class="text-muted" style="font-size:0.75rem;">${formatDateTime(c.updated_at)}</div>
          </div>
        `).join('');

        conversationsList.querySelectorAll('.conv-item').forEach(item => {
          item.addEventListener('click', (e) => {
            if (e.target.closest('.btn-del-conv')) return;
            loadConversation(item.dataset.id);
          });
        });

        conversationsList.querySelectorAll('.btn-del-conv').forEach(btn => {
          btn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (confirm('Delete this investigation conversation?')) {
              deleteConversation(btn.dataset.id);
            }
          });
        });
      })
      .catch(err => console.error('Failed to load conversations:', err));
  }

  // Load Conversation Messages
  function loadConversation(convId) {
    currentConversationId = convId;
    fetch(`/ai-assistant/api/conversations/${convId}`)
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success' && data.conversation) {
          renderMessages(data.conversation.messages || []);
          loadHistory();
        }
      })
      .catch(err => console.error('Failed to load conversation:', err));
  }

  // Delete Conversation
  function deleteConversation(convId) {
    fetch(`/ai-assistant/api/conversations/${convId}`, { method: 'DELETE' })
      .then(res => res.json())
      .then(() => {
        if (currentConversationId === convId) {
          resetChat();
        }
        loadHistory();
      })
      .catch(err => console.error('Failed to delete conversation:', err));
  }

  // Reset to New Chat
  function resetChat() {
    currentConversationId = null;
    chatMessages.innerHTML = `
      <div class="chat-bubble chat-bubble-assistant">
        <div class="d-flex align-items-center mb-2">
          <i class="bi bi-robot text-primary fs-5 me-2"></i>
          <strong class="text-light">CyberDefense XDR Assistant</strong>
          <span class="badge bg-secondary ms-2 small">Tier-3 SOC</span>
        </div>
        <p class="mb-2">Started a new investigation session. I am monitoring your real security database.</p>
        <p class="mb-0 text-muted small">Ask me to investigate an IP address, correlate a recent alert, evaluate a CVE, or suggest incident response playbooks.</p>
      </div>
    `;
    loadHistory();
  }

  btnNewChat.addEventListener('click', resetChat);

  // Send Message
  function sendMessage(text) {
    const prompt = (text || chatInput.value).trim();
    if (!prompt) return;

    chatInput.value = '';
    btnSendMessage.disabled = true;
    sendIcon.className = 'spinner-border spinner-border-sm me-1';

    // Append user bubble immediately
    appendUserBubble(prompt);

    fetch('/ai-assistant/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt: prompt,
        conversation_id: currentConversationId
      })
    })
      .then(res => res.json())
      .then(data => {
        btnSendMessage.disabled = false;
        sendIcon.className = 'bi bi-send me-1';

        if (data.status === 'success') {
          currentConversationId = data.conversation_id;
          appendAssistantBubble(data.message);
          loadHistory();
        } else {
          appendErrorBubble(data.message || 'Failed to generate response.');
        }
      })
      .catch(err => {
        btnSendMessage.disabled = false;
        sendIcon.className = 'bi bi-send me-1';
        console.error('Error sending message:', err);
        appendErrorBubble('Network or server error communicating with AI Assistant.');
      });
  }

  chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    sendMessage();
  });

  // Prompt Starters
  document.querySelectorAll('.prompt-starter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      sendMessage(btn.dataset.prompt);
    });
  });

  // Render Helpers
  function appendUserBubble(text) {
    const div = document.createElement('div');
    div.className = 'chat-bubble chat-bubble-user';
    div.innerHTML = `<div class="fw-semibold mb-1 small text-info"><i class="bi bi-person me-1"></i>Security Analyst</div><div>${escapeHtml(text)}</div>`;
    chatMessages.appendChild(div);
    scrollToBottom();
  }

  function appendAssistantBubble(msg) {
    const div = document.createElement('div');
    div.className = 'chat-bubble chat-bubble-assistant';

    const riskBadge = getRiskBadgeHtml(msg.risk_level);
    const formattedContent = formatAssistantMarkdown(msg.content);

    div.innerHTML = `
      <div class="d-flex justify-content-between align-items-center mb-2">
        <div class="d-flex align-items-center">
          <i class="bi bi-robot text-primary fs-5 me-2"></i>
          <strong class="text-light">CyberDefense XDR Intelligence</strong>
        </div>
        ${riskBadge}
      </div>
      <div class="ai-content-body">${formattedContent}</div>
      <div class="d-flex justify-content-between align-items-center mt-3 pt-2 border-top border-secondary small text-muted">
        <span><i class="bi bi-shield-lock me-1"></i>Advisory Analysis</span>
        <div class="d-flex gap-2">
          <a href="/soar/" class="btn btn-outline-warning btn-xs py-0 px-2">Launch SOAR Playbook <i class="bi bi-lightning-charge ms-1"></i></a>
        </div>
      </div>
    `;

    chatMessages.appendChild(div);
    scrollToBottom();
  }

  function appendErrorBubble(errText) {
    const div = document.createElement('div');
    div.className = 'chat-bubble chat-bubble-assistant border-danger';
    div.innerHTML = `
      <div class="text-danger fw-bold mb-1"><i class="bi bi-exclamation-triangle me-1"></i>Assistant Error</div>
      <div class="text-muted small">${escapeHtml(errText)}</div>
    `;
    chatMessages.appendChild(div);
    scrollToBottom();
  }

  function renderMessages(messages) {
    chatMessages.innerHTML = '';
    messages.forEach(m => {
      if (m.role === 'user') {
        appendUserBubble(m.content);
      } else if (m.role === 'assistant') {
        appendAssistantBubble(m);
      }
    });
    scrollToBottom();
  }

  function scrollToBottom() {
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function formatAssistantMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);

    // Headings
    html = html.replace(/##\s+([A-Z\s&]+)/g, '<h2>$1</h2>');
    html = html.replace(/###\s+([A-Za-z0-9\s&]+)/g, '<h3>$1</h3>');

    // Bold
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong class="text-light">$1</strong>');

    // Bullet points
    html = html.replace(/^- (.*)$/gm, '<li>$1</li>');
    html = html.replace(/<li>.*<\/li>/gs, (match) => `<ul>${match}</ul>`);

    // Numbered lists
    html = html.replace(/^\d+\.\s+(.*)$/gm, '<li>$1</li>');

    // Paragraphs
    html = html.replace(/\n\n/g, '<p></p>');

    return html;
  }

  function getRiskBadgeHtml(level) {
    const l = (level || 'INFORMATIONAL').toUpperCase();
    let bg = 'bg-secondary';
    if (l === 'CRITICAL') bg = 'bg-danger';
    else if (l === 'HIGH') bg = 'bg-warning text-dark';
    else if (l === 'MEDIUM') bg = 'bg-info text-dark';
    else if (l === 'LOW') bg = 'bg-success';
    return `<span class="badge ${bg} cell-mono">${l}</span>`;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function formatDateTime(val) {
    if (!val) return '-';
    try {
      const d = new Date(val);
      if (isNaN(d.getTime())) return String(val);
      return d.toISOString().replace('T', ' ').substring(0, 16);
    } catch {
      return String(val);
    }
  }

  // Pre-seed from URL prompt
  const urlParams = new URLSearchParams(window.location.search);
  const promptParam = urlParams.get('prompt');
  if (promptParam) {
    chatInput.value = promptParam;
    sendMessage(promptParam);
  }

  loadStatus();
  loadHistory();
});

