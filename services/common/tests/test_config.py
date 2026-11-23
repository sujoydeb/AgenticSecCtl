"""WP-1.2 tests: typed configuration (TC-Z10, cross-cutting design Section 6)."""
import unittest

from agenticsecctl_common.config import (
    ConfigError,
    ConfigHolder,
    Field,
    Schema,
    config_changed_event,
    load_config,
)

SCHEMA = Schema({
    "token_lifetime_s": Field(int, default=600, min=1, max=600),        # PAR-F-03 hard bound
    "redirect_hops": Field(int, default=0, min=0, max=3),               # PAR-F-10 hard bound
    "issuer": Field(str, default="https://idp.example"),
    "debug": Field(bool, default=False),
    "ratio": Field(float, default=0.5, min=0.0, max=1.0),
    "db_password": Field(str, secret=True),
})


def layers(**over):
    return dict(file={"db_password": "secretref:db/app"}, env={}, **over)


class Validation(unittest.TestCase):
    def test_defaults_and_layer_precedence(self):
        cfg = load_config(SCHEMA, file={"token_lifetime_s": 300, "db_password": "secretref:a"},
                          env={"token_lifetime_s": 120})
        self.assertEqual(cfg.values["token_lifetime_s"], 120)       # env beats file
        self.assertEqual(cfg.values["redirect_hops"], 0)            # default
        self.assertEqual(cfg.values["issuer"], "https://idp.example")

    def test_unknown_key_rejected(self):
        for layer in ("file", "env"):
            with self.assertRaises(ConfigError) as cm:
                good = {"db_password": "secretref:a"}
                bad = {**good, "tokn": 1}
                load_config(SCHEMA, file=bad if layer == "file" else good, env=bad if layer == "env" else {})
            self.assertIn("tokn", str(cm.exception))

    def test_wrong_type_rejected(self):
        for bad in ({"token_lifetime_s": "300"}, {"token_lifetime_s": True}, {"debug": "yes"},
                    {"ratio": "0.5"}, {"issuer": 5}):
            with self.assertRaises(ConfigError, msg=bad):
                load_config(SCHEMA, file={"db_password": "secretref:a", **bad}, env={})

    def test_out_of_range_rejected_hard_bounds(self):
        for bad in ({"token_lifetime_s": 601}, {"token_lifetime_s": 0}, {"redirect_hops": 4},
                    {"redirect_hops": -1}, {"ratio": 1.5}):
            with self.assertRaises(ConfigError, msg=bad):
                load_config(SCHEMA, file={"db_password": "secretref:a", **bad}, env={})

    def test_all_errors_reported_together(self):
        with self.assertRaises(ConfigError) as cm:
            load_config(SCHEMA, file={"db_password": "secretref:a", "x": 1, "redirect_hops": 9}, env={})
        self.assertEqual(len(cm.exception.errors), 2)

    def test_env_strings_are_coerced(self):
        cfg = load_config(SCHEMA, file={"db_password": "secretref:a"},
                          env={"token_lifetime_s": "90", "debug": "true", "ratio": "0.25"})
        self.assertEqual((cfg.values["token_lifetime_s"], cfg.values["debug"], cfg.values["ratio"]),
                         (90, True, 0.25))
        with self.assertRaises(ConfigError):
            load_config(SCHEMA, file={"db_password": "secretref:a"}, env={"token_lifetime_s": "9x"})

    def test_missing_required(self):
        with self.assertRaises(ConfigError):
            load_config(SCHEMA, file={}, env={})


class Secrets(unittest.TestCase):
    def test_raw_secret_value_refused(self):
        with self.assertRaises(ConfigError) as cm:
            load_config(SCHEMA, file={"db_password": "hunter2"}, env={})
        self.assertNotIn("hunter2", str(cm.exception))

    def test_reference_resolved_at_runtime_only(self):
        cfg = load_config(SCHEMA, file={"db_password": "secretref:db/app"}, env={})
        self.assertEqual(cfg.values["db_password"], "secretref:db/app")
        self.assertEqual(cfg.secret("db_password", lambda ref: "s3cret-for-" + ref), "s3cret-for-db/app")

    def test_repr_and_hash_never_hold_secret_value(self):
        cfg = load_config(SCHEMA, file={"db_password": "secretref:db/app"}, env={})
        cfg.secret("db_password", lambda r: "VALUE")
        self.assertNotIn("VALUE", repr(cfg))
        self.assertNotIn("VALUE", str(cfg.public_view()))


class Versioning(unittest.TestCase):
    def test_hash_stable_and_sensitive(self):
        a = load_config(SCHEMA, file={"db_password": "secretref:a"}, env={})
        b = load_config(SCHEMA, file={"db_password": "secretref:a"}, env={})
        c = load_config(SCHEMA, file={"db_password": "secretref:a", "redirect_hops": 1}, env={})
        self.assertEqual(a.version_hash, b.version_hash)
        self.assertNotEqual(a.version_hash, c.version_hash)
        self.assertEqual(len(a.version_hash), 64)

    def test_changed_event_shape_and_no_secret_values(self):
        a = load_config(SCHEMA, file={"db_password": "secretref:a"}, env={})
        c = load_config(SCHEMA, file={"db_password": "secretref:b", "redirect_hops": 2}, env={})
        ev = config_changed_event(a, c, actor="svc:api")
        self.assertEqual(ev["event"], "config.changed")
        self.assertEqual(ev["actor"], "svc:api")
        self.assertEqual((ev["old_hash"], ev["new_hash"]), (a.version_hash, c.version_hash))
        self.assertEqual(ev["changes"]["redirect_hops"], {"old": 0, "new": 2})
        self.assertEqual(ev["changes"]["db_password"], {"changed": True})


class Holder(unittest.TestCase):
    def test_start_with_invalid_config_fails(self):
        with self.assertRaises(ConfigError):
            ConfigHolder.start(SCHEMA, file={"redirect_hops": 9}, env={})

    def test_reload_invalid_keeps_last_valid(self):
        h = ConfigHolder.start(SCHEMA, file={"db_password": "secretref:a"}, env={})
        before = h.current.version_hash
        err = h.reload(file={"db_password": "secretref:a", "redirect_hops": 99}, env={})
        self.assertIsInstance(err, ConfigError)
        self.assertEqual(h.current.version_hash, before)

    def test_reload_valid_returns_event(self):
        h = ConfigHolder.start(SCHEMA, file={"db_password": "secretref:a"}, env={})
        ev = h.reload(file={"db_password": "secretref:a", "redirect_hops": 1}, env={}, actor="op")
        self.assertEqual(ev["event"], "config.changed")
        self.assertEqual(h.current.values["redirect_hops"], 1)

    def test_reload_unchanged_returns_none(self):
        h = ConfigHolder.start(SCHEMA, file={"db_password": "secretref:a"}, env={})
        self.assertIsNone(h.reload(file={"db_password": "secretref:a"}, env={}))


if __name__ == "__main__":
    unittest.main()
