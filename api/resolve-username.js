import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  try {
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

    if (!supabaseUrl) {
      console.error('Missing SUPABASE_URL environment variable');

      return res.status(500).json({
        error: 'Server configuration error: SUPABASE_URL is missing.'
      });
    }

    if (!supabaseSecretKey) {
      console.error('Missing SUPABASE_SECRET_KEY environment variable');

      return res.status(500).json({
        error: 'Server configuration error: SUPABASE_SECRET_KEY is missing.'
      });
    }

    const supabaseAdmin = createClient(
      supabaseUrl,
      supabaseSecretKey,
      {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      }
    );

    const { action = 'resolve', username } = req.body || {};

    const cleanUsername = String(username || '')
      .trim()
      .toLowerCase();

    if (!/^[a-z0-9_-]{3,20}$/i.test(cleanUsername)) {
      return res.status(400).json({
        error:
          'Username must be 3-20 characters and use only letters, numbers, underscores, or hyphens.'
      });
    }

    const { data, error } = await supabaseAdmin
      .from('user_progress')
      .select('username, email')
      .ilike('username', cleanUsername)
      .maybeSingle();

    if (error) {
      console.error('Supabase username lookup failed:', {
        message: error.message,
        code: error.code,
        details: error.details
      });

      return res.status(500).json({
        error: 'Username lookup failed.'
      });
    }

    // Used when creating an account
    if (action === 'check') {
      return res.status(200).json({
        available: !data
      });
    }

    // Used when logging in with a username
    if (!data?.email) {
      return res.status(401).json({
        error: 'Invalid credentials.'
      });
    }

    return res.status(200).json({
      email: data.email
    });

  } catch (error) {
    console.error('Unexpected resolve-username error:', error);

    return res.status(500).json({
      error: 'Unable to process request.'
    });
  }
}
