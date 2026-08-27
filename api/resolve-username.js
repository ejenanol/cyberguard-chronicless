import { createClient } from '@supabase/supabase-js';

function isValidUsername(username) {
  return /^[a-z0-9_-]{3,20}$/i.test(username);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed.'
    });
  }

  try {
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

    if (!supabaseUrl) {
      console.error('Missing SUPABASE_URL environment variable.');
      return res.status(500).json({
        error: 'Server configuration error.'
      });
    }

    if (!supabaseSecretKey) {
      console.error('Missing SUPABASE_SECRET_KEY environment variable.');
      return res.status(500).json({
        error: 'Server configuration error.'
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

    const body = req.body || {};
    const action = body.action || 'resolve';

    const cleanUsername = String(body.username || '')
      .trim()
      .toLowerCase();

    if (!isValidUsername(cleanUsername)) {
      return res.status(400).json({
        error:
          'Username must be 3-20 characters and contain only letters, numbers, underscores, or hyphens.'
      });
    }

    const { data, error } = await supabaseAdmin
      .from('user_progress')
      .select('username, email')
      .ilike('username', cleanUsername)
      .maybeSingle();

    if (error) {
      console.error('Username lookup failed:', {
        message: error.message,
        code: error.code
      });

      return res.status(500).json({
        error: 'Unable to process username request.'
      });
    }

    /*
      SIGNUP:
      Check whether the username already exists.
    */
    if (action === 'check') {
      return res.status(200).json({
        available: !data
      });
    }

    /*
      LOGIN:
      Resolve username to email.

      Password verification NEVER happens here.
      The frontend sends the returned email + password
      directly to Supabase Auth.
    */
    if (action === 'resolve') {
      if (!data?.email) {
        return res.status(401).json({
          error: 'Invalid credentials.'
        });
      }

      return res.status(200).json({
        email: data.email
      });
    }

    return res.status(400).json({
      error: 'Invalid action.'
    });

  } catch (error) {
    console.error('Unexpected resolve-username error:', error);

    return res.status(500).json({
      error: 'Unable to process request.'
    });
  }
}
