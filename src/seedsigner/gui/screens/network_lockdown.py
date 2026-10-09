"""
    The screen a network tripwire trip leaves on the display
    (models/network_tripwire.py). Drawn straight onto the display, not
    through a View, so nothing can navigate away from it, and it has no
    buttons: the process ends right after it is drawn and only a power-off
    brings the device back.
"""
import textwrap

from PIL import Image, ImageDraw

from seedsigner.gui.components import Fonts, GUIConstants

HEADLINE = "NETWORK DETECTED"
BODY = ("Signing is disabled and the seeds were cleared from memory. Power off now. "
        "If this happens again, this card or image is the wrong one.")
_WRAP = 24          # characters per line at the body size on a 240px display
_FINDING_WRAP = 30


def render_network_lockdown(width: int, height: int, findings) -> Image.Image:
    image = Image.new("RGB", (width, height), GUIConstants.ERROR_COLOR)
    draw = ImageDraw.Draw(image)
    edge = GUIConstants.EDGE_PADDING
    headline_font = Fonts.get_font(GUIConstants.get_top_nav_title_font_name(), GUIConstants.get_top_nav_title_font_size())
    body_font = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.BODY_FONT_MIN_SIZE)

    y = edge
    draw.text((width // 2, y), HEADLINE, font=headline_font, fill="white", anchor="mt")
    y += headline_font.size + 2 * GUIConstants.COMPONENT_PADDING
    for line in textwrap.wrap(BODY, _WRAP):
        draw.text((edge, y), line, font=body_font, fill="white")
        y += body_font.size + 4
    if findings:
        y += GUIConstants.COMPONENT_PADDING
        for line in textwrap.wrap(str(findings[0]), _FINDING_WRAP)[:2]:
            draw.text((edge, y), line, font=body_font, fill="black")
            y += body_font.size + 4
    return image
