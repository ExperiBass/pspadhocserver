copyin https://github.com/Souler/ppsspp-adhoc-server/ to understand how adhoc works (and to maybe make a better clone?)
prolly 100% terrible
needs a lot of work, search for TODO and MAYBE if you care
the end goal is to get a full-featured adhoc server, including
- web status page like socom.cc (its quite nice, if a bit janky because of the unfold on hover)
- proxying of connections (i dont see many people with upnp enabled nowadays) or hole punching ([holepunch.to](https://holepunch.to)?)
- - adhoc client would need to be implemented too for proxying
- - hole punch is probably the better option
- - sync required? especially for LAN adhoc games, net ping is too much
- clustering support
maybe ill port it to a more-performant language afterwards