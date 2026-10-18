# Design principles

Checklist for reviewing and building UI in this repo. Derived from Steve Krug, *Don't Make Me Think, Revisited* (2014), chapters 1, 3, and 5. Paraphrased, not quoted.

## Core rule

- **Don't make me think.** Every screen should be understandable at a glance, without effort. Reading a page is slower than scanning it.

## Scanning and hierarchy (ch. 3)

- Use conventions. Standard patterns (buttons that look like buttons, links in the usual places, familiar icons) beat clever reinvention. Innovate only when the new version is clearly better.
- The most important element is the most prominent: largest, boldest, distinct color, most white space, or closest to the top.
- Related things look related (grouped under a heading, same style, or in a clear area). Nested things are visually nested.
- Headings sit closer to the section they introduce than to the one before. Each heading level is visibly distinct.
- Break the page into clearly defined areas.
- Make clickable things look clickable: shape, location, or color. Don't give non-clickable headings the link color.
- Remove noise. Assume every element is noise until it earns its place. Avoid shouting (too many emphasis styles), disorganization (no grid), and clutter.

## Clarity (ch. 5)

- Clarity beats consistency when a slight inconsistency makes something significantly clearer.
- Omit unnecessary words. Labels and status text should say what the thing is or does, nothing more.

## Type and contrast (ch. 3, 12)

- Never use small, low-contrast text. Use large low-contrast or small high-contrast type.
- Keep text and background contrast high. Light gray on dark gray is not acceptable.
- Everything must work by keyboard.

## Restraint on color (ch. 13)

- Users rarely leave a site because of its colors. Don't spend review time on color preference. Change color only when it hurts clarity, contrast, or hierarchy.

## Hierarchy beyond size (Refactoring UI, Wathan and Schoger)

- Don't rely on font size alone. Use weight or color to make primary content stand out.
- Use two or three colors for text (primary, secondary, tertiary) and two weights (normal, emphasis). Avoid weights under 400 for UI text.
- Emphasize by de-emphasizing: soften competing elements instead of boosting the target. Remove a background from a sidebar that competes with the content.
- Don't use grey text on colored backgrounds. Hand-pick a tinted color of the same hue.
- Labels are a last resort. Let format and context carry meaning, or combine label and value ("12 left in stock"). When a label is needed, make it supporting content.
- Visual hierarchy is separate from document hierarchy. An h1 doesn't have to look like one. Section titles are usually small.
- Actions have a pyramid: one solid primary button, outlined secondary buttons, link-styled tertiary actions. Don't make destructive actions loud unless they are the primary action on a confirmation step.

## Spacing and layout

- Start with too much white space and remove it. Add room only when something looks wrong.
- Use a constrained spacing and sizing scale (e.g. built from 16px) instead of arbitrary pixel values. Adjacent values should differ by roughly 25% or more.
- Group by spacing: space between groups must be larger than space within a group. Form labels sit closer to their own input than to the field above.
- Don't fill the screen by default. Give content a max-width and let it shrink only when the screen is narrower than that.
- Don't scale every element proportionally. Let small and large elements have independent sizes at each breakpoint.

## Type, color, and depth

- Keep line length in check and use a real type scale.
- Build color from a fixed set of shades (about 9 per color) defined up front, not generated on the fly.
- Keep text contrast at or above 4.5:1 for normal text and 3:1 for large text. If light text on a colored background is too bright, use dark text on a light background of the same hue.
- Don't rely on color alone. Pair it with an icon, text, or contrast.
- Use shadows to show elevation and as few borders as possible.

## Affordances, signifiers, and feedback (The Design of Everyday Things, Don Norman, rev. 2013)

- Make the possible actions discoverable. If a control's function can't be seen, add a signifier: a label, an icon, a shape, or a cursor change.
- Don't add signs to fix bad hardware. Needing "Push" or "Pull" labels means the design already failed. Make the control itself show its use.
- Map controls to what they do. Group related controls. Put a control near what it controls.
- Give feedback immediately, and in a way that says what is happening. Any action that takes time needs an in-progress state ("Connecting…"), not just a disabled button. If an action fails, show the real state and the error.
- Feedback should be informative and proportionate. Don't add alerts for minor events; prioritize important ones.
- Build a conceptual model the user can form from the screen: what is connected, what is pending, and what the next action will do.

## Review questions

1. What is the first thing the eye lands on, and is it the most important thing?
2. Can I tell what is clickable without moving the cursor?
3. Are related items grouped and unrelated items separated?
4. Does any text fail contrast or fall below about 12px?
5. What on this screen can be removed without losing information?
