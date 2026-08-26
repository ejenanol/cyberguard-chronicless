import { createClient } from '@supabase/supabase-js';

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

const validUsername = (value) =>
  /^[a-z0-9_-]{3,20}$/i.test(String(value || '').trim());

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  try {
    const { action = 'resolve', username } = req.body || {};

    const cleanUsername = String(username || '')
      .trim()
      .toLowerCase();

    if (!validUsername(cleanUsername)) {
      return res.status(400).json({
        error: 'Invalid username.'
      });
    }

    const { data, error } = await supabaseAdmin
      .from('user_progress')
      .select('username, email')
      .eq('username', cleanUsername)
      .maybeSingle();

    if (error) {
      console.error(
        'Username lookup failed:',
        error.message
      );

      return res.status(500).json({
        error: 'Unable to process request.'
      });
    }

    // Used during signup to check whether a username is available.
    if (action === 'check') {
      return res.status(200).json({
        available: !data
      });
    }

    // Generic response prevents unnecessary username enumeration.
    if (!data?.email) {
      return res.status(401).json({
        error: 'Invalid credentials.'
      });
    }

    // Return the email so the frontend can pass it to
    // Supabase Auth for password verification.
    return res.status(200).json({
      email: data.email
    });

  } catch (error) {
    console.error(
      'Unexpected username endpoint error:',
      error
    );

    return res.status(500).json({
      error: 'Unable to process request.'
    });
  }
}
