using System.Globalization;
using System.Net;
using System.Text;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// The content of a branded account e-mail, described once and rendered to both the HTML card
/// (<see cref="BrandedEmail.RenderHtml"/>) and its plain-text alternative (<see cref="BrandedEmail.RenderText"/>),
/// so the two parts cannot drift apart.
/// </summary>
public sealed record BrandedEmailContent
{
    /// <summary>Card heading (HTML-encoded on render).</summary>
    public required string Title { get; init; }

    /// <summary>Body paragraphs before the call-to-action (each HTML-encoded on render).</summary>
    public IReadOnlyList<string> Paragraphs { get; init; } = [];

    /// <summary>Call-to-action button label. Rendered only together with <see cref="ActionUrl"/>.</summary>
    public string? ButtonText { get; init; }

    /// <summary>Call-to-action / single-use link. Also emitted as a plain-text fallback under the button.</summary>
    public string? ActionUrl { get; init; }

    /// <summary>Muted footer note.</summary>
    public string? FooterNote { get; init; }

    /// <summary>Card-header brand — the host-configured product name (see <c>KeywardUiOptions</c>).</summary>
    public string Brand { get; init; } = "AM KEYWARD";
}

/// <summary>
/// Renders <see cref="BrandedEmailContent"/> in the shared Ardimedia card layout — a light page background, a
/// white centred card with an "AM KEYWARD · Ardimedia" header, a bold title, body paragraphs, a "bulletproof"
/// CTA button (padding on the table cell so Outlook Classic's Word engine renders it like modern clients) and a
/// muted footer. Email-client-safe: table layout, inline CSS only, no images. All dynamic text is HTML-encoded.
/// This is a focused, self-contained port of the amvs <c>Am.App.MessageTemplates</c> card (that library lives on
/// the private am-private feed and cannot be referenced from this public repo); keep the look in sync with it.
/// See the global <c>email-typography.md</c> rule for the sizes (body 11pt, footer 9pt/12px).
/// </summary>
public static class BrandedEmail
{
    private const string CompanyName = "Ardimedia";
    private const string FontStack = "Aptos,'Segoe UI',Arial,sans-serif";
    private const string BodyFontSize = "11pt";   // Outlook Classic compose default (email-typography.md)
    private const int CardWidthPx = 640;

    // Print-only progressive enhancement: print-capable clients drop the page/card chrome and use full A4 width;
    // Outlook Classic ignores @page/@media print and keeps the inline layout, so this never regresses it.
    private const string PrintStyles =
        "<style>" +
        "@page{size:A4;margin:12mm}" +
        "@media print{" +
        "body{background:#ffffff !important}" +
        ".am-page{background:#ffffff !important;padding:0 !important}" +
        ".am-card{width:100% !important;border:0 !important;border-radius:0 !important}" +
        ".am-head,.am-body,.am-foot{padding-left:0 !important;padding-right:0 !important}" +
        ".am-body{padding-top:0 !important}" +
        "}" +
        "</style>";

    /// <summary>Renders the full HTML document (branded card) for <paramref name="content"/>.</summary>
    public static string RenderHtml(BrandedEmailContent content)
    {
        ArgumentNullException.ThrowIfNull(content);

        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
        html.Append(PrintStyles);
        html.Append("</head><body style=\"margin:0;padding:0;background-color:#f4f4f5;\">");
        html.Append("<table role=\"presentation\" class=\"am-page\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color:#f4f4f5;padding:32px 0;\"><tr><td align=\"center\">");
        html.Append(CultureInfo.InvariantCulture, $"<table role=\"presentation\" class=\"am-card\" width=\"{CardWidthPx}\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width:{CardWidthPx}px;width:100%;background-color:#ffffff;border:1px solid #e4e4e7;border-radius:8px;font-family:{FontStack};\">");

        // Branding header
        html.Append("<tr><td class=\"am-head\" style=\"padding:20px 32px;border-bottom:1px solid #e4e4e7;\">");
        html.Append(CultureInfo.InvariantCulture, $"<span style=\"font-size:16px;font-weight:600;color:#18181b;letter-spacing:0.02em;\">{Encode(content.Brand)}</span>");
        html.Append(CultureInfo.InvariantCulture, $"<span style=\"font-size:13px;color:#71717a;\">&nbsp;&middot;&nbsp;{Encode(CompanyName)}</span>");
        html.Append("</td></tr>");

        // Body
        html.Append("<tr><td class=\"am-body\" style=\"padding:32px;\">");
        html.Append(CultureInfo.InvariantCulture, $"<h1 style=\"margin:0 0 12px;font-size:{BodyFontSize};font-weight:bold;line-height:1.3;color:#18181b;\">{Encode(content.Title)}</h1>");

        foreach (var paragraph in content.Paragraphs)
        {
            html.Append(CultureInfo.InvariantCulture, $"<p style=\"margin:0 0 12px;font-size:{BodyFontSize};line-height:1.6;color:#3f3f46;\">{Encode(paragraph)}</p>");
        }

        if (!string.IsNullOrWhiteSpace(content.ButtonText) && !string.IsNullOrWhiteSpace(content.ActionUrl))
        {
            var url = Encode(content.ActionUrl);
            html.Append("<div style=\"height:16px;line-height:16px;font-size:1px;\">&nbsp;</div>");
            html.Append("<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>");
            html.Append("<td align=\"center\" bgcolor=\"#18181b\" style=\"background-color:#18181b;border-radius:6px;padding:12px 28px;\">");
            html.Append(CultureInfo.InvariantCulture, $"<a href=\"{url}\" style=\"display:inline-block;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;\"><span style=\"color:#ffffff;\">{Encode(content.ButtonText)}</span></a>");
            html.Append("</td></tr></table>");
            html.Append("<div style=\"height:24px;line-height:24px;font-size:1px;\">&nbsp;</div>");
            html.Append("<p style=\"margin:0 0 4px;font-size:12px;line-height:1.5;color:#71717a;\">If the button does not work, open this link:</p>");
            html.Append(CultureInfo.InvariantCulture, $"<p style=\"margin:0 0 12px;font-size:12px;line-height:1.5;word-break:break-all;\"><a href=\"{url}\" style=\"color:#2563eb;text-decoration:underline;\">{url}</a></p>");
        }

        html.Append("</td></tr>");

        // Footer
        if (!string.IsNullOrWhiteSpace(content.FooterNote))
        {
            html.Append("<tr><td class=\"am-foot\" style=\"padding:16px 32px;border-top:1px solid #e4e4e7;\">");
            html.Append(CultureInfo.InvariantCulture, $"<p style=\"margin:0;font-size:12px;line-height:1.5;color:#a1a1aa;\">{Encode(content.FooterNote)}</p>");
            html.Append("</td></tr>");
        }

        html.Append("</table></td></tr></table></body></html>");
        return html.ToString();
    }

    /// <summary>Renders the plain-text alternative for <paramref name="content"/> (same source content).</summary>
    public static string RenderText(BrandedEmailContent content)
    {
        ArgumentNullException.ThrowIfNull(content);

        var sb = new StringBuilder();
        sb.Append(content.Title).Append("\r\n\r\n");

        foreach (var paragraph in content.Paragraphs)
        {
            sb.Append(paragraph).Append("\r\n\r\n");
        }

        if (!string.IsNullOrWhiteSpace(content.ActionUrl))
        {
            sb.Append(content.ActionUrl).Append("\r\n\r\n");
        }

        if (!string.IsNullOrWhiteSpace(content.FooterNote))
        {
            sb.Append(content.FooterNote).Append("\r\n");
        }

        return sb.ToString();
    }

    private static string Encode(string value) => WebUtility.HtmlEncode(value);
}
