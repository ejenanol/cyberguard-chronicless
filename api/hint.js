export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { title } = req.body;

  if (!title) {
    return res.status(400).json({ error: 'Missing title' });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 200,
        messages: [{
          role: 'user',
          content: `You are Maya Chen, cybersecurity mentor in a training RPG. A beginner is stuck on: "${title}". Give a helpful, encouraging hint in 2-3 sentences WITHOUT giving away the answer. Be friendly, use simple language. No markdown.`
        }]
      })
    });

    const data = await response.json();
    const hint = data.content?.[0]?.text || 'Think carefully about what looks unusual or out of place.';
    return res.status(200).json({ hint });

  } catch (error) {
    console.error('Anthropic API error:', error);
    return res.status(500).json({ hint: 'Think carefully about what looks unusual or out of place.' });
  }
}
