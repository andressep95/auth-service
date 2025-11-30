package email

import "fmt"

// VerificationEmailTemplate generates HTML for email verification
func VerificationEmailTemplate(name, verificationURL string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" style="width: 100%%; border-collapse: collapse;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 30px; text-align: center; background-color: #4F46E5; border-radius: 8px 8px 0 0;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px;">Verify Your Email</h1>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 24px; color: #333333;">
                                Hi %s,
                            </p>
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 24px; color: #333333;">
                                Thank you for registering! Please verify your email address by clicking the button below:
                            </p>
                            <table role="presentation" style="margin: 30px 0;">
                                <tr>
                                    <td align="center">
                                        <a href="%s" style="display: inline-block; padding: 14px 40px; background-color: #4F46E5; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: bold;">Verify Email</a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 20px 0 0; font-size: 14px; line-height: 20px; color: #666666;">
                                If you didn't create an account, you can safely ignore this email.
                            </p>
                            <p style="margin: 20px 0 0; font-size: 14px; line-height: 20px; color: #666666;">
                                This link will expire in 24 hours.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 30px; text-align: center; background-color: #f8f8f8; border-radius: 0 0 8px 8px;">
                            <p style="margin: 0; font-size: 12px; line-height: 18px; color: #999999;">
                                © 2024 Auth Service. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`, name, verificationURL)
}

// PasswordResetEmailTemplate generates HTML for password reset
func PasswordResetEmailTemplate(name, resetURL string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" style="width: 100%%; border-collapse: collapse;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 30px; text-align: center; background-color: #EF4444; border-radius: 8px 8px 0 0;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px;">Reset Your Password</h1>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 24px; color: #333333;">
                                Hi %s,
                            </p>
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 24px; color: #333333;">
                                We received a request to reset your password. Click the button below to create a new password:
                            </p>
                            <table role="presentation" style="margin: 30px 0;">
                                <tr>
                                    <td align="center">
                                        <a href="%s" style="display: inline-block; padding: 14px 40px; background-color: #EF4444; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: bold;">Reset Password</a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 20px 0 0; font-size: 14px; line-height: 20px; color: #666666;">
                                If you didn't request a password reset, please ignore this email or contact support if you have concerns.
                            </p>
                            <p style="margin: 20px 0 0; font-size: 14px; line-height: 20px; color: #666666;">
                                This link will expire in 1 hour for security reasons.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 30px; text-align: center; background-color: #f8f8f8; border-radius: 0 0 8px 8px;">
                            <p style="margin: 0; font-size: 12px; line-height: 18px; color: #999999;">
                                © 2024 Auth Service. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`, name, resetURL)
}

// WelcomeEmailTemplate generates HTML for welcome email
func WelcomeEmailTemplate(name string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome!</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" style="width: 100%%; border-collapse: collapse;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 30px; text-align: center; background-color: #10B981; border-radius: 8px 8px 0 0;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px;">Welcome! 🎉</h1>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 24px; color: #333333;">
                                Hi %s,
                            </p>
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 24px; color: #333333;">
                                Your email has been successfully verified! Welcome to our community.
                            </p>
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 24px; color: #333333;">
                                You can now enjoy full access to all features. If you have any questions, feel free to reach out to our support team.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 30px; text-align: center; background-color: #f8f8f8; border-radius: 0 0 8px 8px;">
                            <p style="margin: 0; font-size: 12px; line-height: 18px; color: #999999;">
                                © 2024 Auth Service. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`, name)
}

// PasswordChangedEmailTemplate generates HTML for password changed notification
func PasswordChangedEmailTemplate(name string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Changed</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" style="width: 100%%; border-collapse: collapse;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 30px; text-align: center; background-color: #F59E0B; border-radius: 8px 8px 0 0;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px;">Password Changed</h1>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 24px; color: #333333;">
                                Hi %s,
                            </p>
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 24px; color: #333333;">
                                This is a confirmation that your password has been successfully changed.
                            </p>
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 24px; color: #333333;">
                                If you didn't make this change, please contact our support team immediately.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 30px; text-align: center; background-color: #f8f8f8; border-radius: 0 0 8px 8px;">
                            <p style="margin: 0; font-size: 12px; line-height: 18px; color: #999999;">
                                © 2024 Auth Service. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`, name)
}
