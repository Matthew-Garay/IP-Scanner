"""Everything that touches tkinter.

The only layer allowed to know about widgets, and the only one the core may
never import. ``ui`` owns behaviour and layout; ``theme`` owns the palette
and the composed result rows. The bilingual catalogue stays one level up, in
``ip_inspector.i18n``, because the report writer needs it too.
"""
