# SPDX-License-Identifier: Apache-2.0
"""Fail-closed plugin configuration and composition errors."""


class PluginCompositionError(RuntimeError):
    """Bootstrap could not produce a complete, known composition."""


class UnknownPluginInterface(PluginCompositionError):
    """Configuration or provider registration names an unknown interface."""


class UnknownPluginInterfaceVersion(PluginCompositionError):
    """A configured interface version is not an integer version supported here."""


class MissingPluginProvider(PluginCompositionError):
    """Configuration does not name a provider for every required interface."""


class UnknownPluginProvider(PluginCompositionError):
    """Configuration names a provider that discovery did not find."""


class AmbiguousPluginProvider(PluginCompositionError):
    """More than one entry point claims the configured provider name."""


class InvalidPluginProvider(PluginCompositionError):
    """A selected entry point does not implement its declared interface."""


class InvalidCompositionEvidence(PluginCompositionError):
    """The evidence sink did not return the requested composition chain entry."""
