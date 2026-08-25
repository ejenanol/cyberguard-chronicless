import { createClient } from '@supabase/supabase-js';

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  }
);

export default async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  try {
    const { email } = req.body || {};

    // Basic validation
    if (
      typeof email !== 'string' ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return res.status(400).json({
        error: 'Please enter a valid email address.'
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // Send the Supabase account setup invitation
    const { error } =
      await supabaseAdmin.auth.admin.inviteUserByEmail(
        cleanEmail,
        {
          redirectTo: process.env.APP_URL
        }
      );

    if (error) {
      console.error('Invite error:', error.message);

      // Generic response helps reduce account enumeration.
      return res.status(200).json({
        message:
          'If this email can receive an invitation, a setup email will be sent shortly.'
      });
    }

    return res.status(200).json({
      message:
        'If this email can receive an invitation, a setup email will be sent shortly.'
    });

  } catch (error) {
    console.error('Unexpected invite error:', error);

    return res.status(500).json({
      error: 'Unable to process the request. Please try again later.'
    });
  }
}
