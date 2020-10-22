hook Notice::policy(n: Notice::Info)
{
  if ( n$note == SIP::BadUserAgent)
        {
              #add n$actions[Notice::ACTION_EMAIL];
              add n$actions[Notice::ACTION_DROP];
        }

  if ( n$note == SIP::SIP_403_Forbidden)
        {
              #add n$actions[Notice::ACTION_EMAIL];
              add n$actions[Notice::ACTION_DROP];
        }

 if ( n$note == SIP::SIP_401_Unauthorized)
        {
              #add n$actions[Notice::ACTION_EMAIL];
              add n$actions[Notice::ACTION_DROP];
        }

 if ( n$note == SIP::Code_401_403)
        {
              #add n$actions[Notice::ACTION_EMAIL];
              add n$actions[Notice::ACTION_DROP];
        }

  if ( n$note == SIP::SipviciousScan)
        {
              #add n$actions[Notice::ACTION_EMAIL];
              add n$actions[Notice::ACTION_DROP];
        }
}
