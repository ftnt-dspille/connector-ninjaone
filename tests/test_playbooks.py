"""Structural checks on the shipped playbook collection.

playbooks.json is generated, so these do not re-test the compiler. They guard
the seam between the two artifacts: a playbook that references an operation
info.json no longer declares imports cleanly and fails only when someone runs
it, because nothing in FortiSOAR validates that contract at import time.
"""

import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYBOOKS = os.path.join(ROOT, 'ninjaone', 'playbooks', 'playbooks.json')
INFO = os.path.join(ROOT, 'ninjaone', 'info.json')

STEP_IRI = re.compile(r'^/api/3/workflow_steps/([0-9a-f-]+)$')


@pytest.fixture(scope='module')
def collection():
    if not os.path.exists(PLAYBOOKS):
        pytest.skip('no compiled playbooks; run ./tools/build_playbooks.sh')
    return json.load(open(PLAYBOOKS, encoding='utf-8'))['data'][0]


@pytest.fixture(scope='module')
def declared_operations():
    return {op['operation'] for op in json.load(open(INFO, encoding='utf-8'))['operations']}


def test_collection_ships_playbooks(collection):
    assert collection['name'].startswith('Sample - NinjaOne')
    assert len(collection['workflows']) >= 5


def test_every_route_points_at_a_real_step(collection):
    for workflow in collection['workflows']:
        uuids = {step['uuid'] for step in workflow['steps']}
        for route in workflow.get('routes') or []:
            for end in ('sourceStep', 'targetStep'):
                match = STEP_IRI.match(route[end] or '')
                assert match, f"{workflow['name']}: {end} is not a step IRI"
                assert match.group(1) in uuids, \
                    f"{workflow['name']}: {end} of route {route.get('name')!r} is dangling"


def test_every_workflow_has_a_reachable_trigger(collection):
    for workflow in collection['workflows']:
        uuids = {step['uuid'] for step in workflow['steps']}
        match = STEP_IRI.match(workflow.get('triggerStep') or '')
        assert match, f"{workflow['name']}: no triggerStep"
        assert match.group(1) in uuids, f"{workflow['name']}: triggerStep is not one of its steps"


def test_step_uuids_are_unique(collection):
    for workflow in collection['workflows']:
        uuids = [step['uuid'] for step in workflow['steps']]
        assert len(uuids) == len(set(uuids)), f"{workflow['name']}: duplicate step uuid"


def test_playbooks_only_call_declared_operations(collection, declared_operations):
    """The seam that nothing else checks."""
    used = set()
    for workflow in collection['workflows']:
        for step in workflow['steps']:
            args = step.get('arguments') or {}
            if args.get('connector') and args.get('operation'):
                assert args['connector'] == 'ninjaone', \
                    f"{workflow['name']}: unexpected connector {args['connector']!r}"
                used.add(args['operation'])
    assert used, 'no connector steps found at all'
    assert not (used - declared_operations), \
        f'playbooks call operations info.json does not declare: {sorted(used - declared_operations)}'


def test_no_playbook_calls_run_script(collection):
    """run_script cannot work on a client-credentials configuration.

    NinjaOne answers 403 "Access key does not have user context". A shipped
    sample built on it would fail for every user who imported the connector, so
    this is a deliberate exclusion worth defending against a well-meaning edit.
    """
    for workflow in collection['workflows']:
        for step in workflow['steps']:
            args = step.get('arguments') or {}
            assert args.get('operation') != 'run_script', \
                f"{workflow['name']} calls run_script, which cannot work with this auth model"
