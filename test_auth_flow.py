"""Offline regression tests for native registration flow consistency."""
import json
import unittest
from unittest.mock import MagicMock, patch

import example_register
from musepy.client import MuseClient, MuseError


class NativeAuthFlowTests(unittest.TestCase):
    def test_same_flow_id_and_dynamic_terms_across_registration(self):
        session = MagicMock()
        def response(status, data):
            result = MagicMock(status_code=status)
            result.json.return_value = data
            return result
        session.post.side_effect = [
            response(201, {"csrf_token": "csrf-first"}),
            response(201, {}),
            response(200, {"registration_state": "completion_required",
                           "tos": {"content_version": "server-current-terms"}}),
            response(200, {"auth_meta_session": {"frl_account_id": "test-account"}}),
            response(201, {"csrf_token": "csrf-second"}),
        ]
        with patch("musepy.client.cr.Session", return_value=session):
            client = MuseClient()
        client.restart()
        client.send_otp("test@example.invalid")
        client.confirm_otp("000000")
        client.register_completion("1993-11-14", "Test", "User")
        calls = session.post.call_args_list
        ids = [call.kwargs["headers"]["X-Hatch-Waterfall-Id"] for call in calls]
        self.assertEqual(len(set(ids)), 1)
        self.assertTrue(ids[0])
        for call in calls[1:]:
            self.assertEqual(call.kwargs["headers"]["X-Hatch-CSRF-Token"], "csrf-first")
        self.assertEqual(json.loads(calls[-1].kwargs["data"])["tos_content_version"],
                         "server-current-terms")
        client.restart()
        self.assertNotEqual(client.waterfall_id, ids[0])
        self.assertNotIn("X-Hatch-CSRF-Token", session.post.call_args.kwargs["headers"])

    def test_does_not_create_account_for_other_confirmation_state(self):
        config = {"email": "test@example.invalid", "send_caa": False,
                  "send_falco": False, "otp_file": ""}
        client = MagicMock()
        client.confirm_otp.return_value = {"registration_state": "password_required"}
        with patch.object(example_register, "load_config", return_value=config), \
             patch.object(example_register, "MuseClient", return_value=client), \
             patch("builtins.input", return_value="000000"):
            with self.assertRaisesRegex(MuseError, "password_required"):
                example_register.main()
        client.register_completion.assert_not_called()


if __name__ == "__main__":
    unittest.main()
