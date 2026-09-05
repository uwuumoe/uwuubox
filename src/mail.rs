//! Outbound mail (password resets). Present only when `UWUU_SMTP_HOST` is
//! set; otherwise the reset endpoints explain mail is unconfigured.

use lettre::{
    message::SinglePart,
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

use crate::config::Env;

#[derive(Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
}

impl Mailer {
    pub fn from_env(env: &Env) -> Option<Self> {
        let host = env.smtp_host.clone()?;
        let from = env.smtp_from.clone()?;
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host.as_str())
            .port(env.smtp_port);
        builder = if env.smtp_starttls {
            match TlsParameters::new(host.clone()) {
                Ok(tls) => builder.tls(Tls::Required(tls)),
                Err(e) => {
                    tracing::warn!(error = %e, "mailer: bad TLS params; mail disabled");
                    return None;
                }
            }
        } else {
            builder.tls(Tls::None)
        };
        if let (Some(user), Some(pass)) = (env.smtp_user.clone(), env.smtp_pass.clone()) {
            builder = builder.credentials(Credentials::new(user, pass));
        }
        Some(Self {
            transport: builder.build(),
            from,
        })
    }

    pub async fn send_password_reset(&self, to: &str, link: &str) -> Result<(), String> {
        let msg = Message::builder()
            .from(self.from.parse().map_err(|e| format!("bad from: {e}"))?)
            .to(to.parse().map_err(|_| "bad recipient".to_string())?)
            .subject("uwuubox password reset")
            .singlepart(SinglePart::plain(format!(
                "Someone requested a password reset for your uwuubox account.\n\n\
                     Open this link within 1 hour to set a new password:\n{link}\n\n\
                     If that was not you, ignore this mail."
            )))
            .map_err(|e| format!("build mail: {e}"))?;
        self.transport
            .send(msg)
            .await
            .map_err(|e| format!("send mail: {e}"))?;
        Ok(())
    }
}
