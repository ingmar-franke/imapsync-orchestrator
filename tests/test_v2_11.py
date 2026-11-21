import contextlib
import copy
import hashlib
import importlib.util
import os
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
import sys

P = Path(__file__).resolve().parents[1] / 'imap_orchestrator_v2_11.py'
spec = importlib.util.spec_from_file_location('public_v211_tests', P)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
with mock.patch.dict(os.environ, {k:v for k,v in os.environ.items() if not k.startswith('IMAP_')}, clear=True):
    spec.loader.exec_module(mod)

class PublicPrivacyTests(unittest.TestCase):
    def _env(self):
        return dict(IMAP_SOURCE_HOST='imap.example.org', IMAP_TARGET_HOST='imap.example.org',
                    IMAP_SOURCE_USER='source@example.org', IMAP_TARGET_USER='target@example.org',
                    IMAP_OAUTH_REFRESH_SCRIPT='/private/example/oauth_refresh.py',
                    IMAP_ACCESS_TOKEN_FILE='/private/example/access_token.txt')

    def test_unconfigured_defaults_and_fail_closed_gaps(self):
        self.assertEqual((mod.SRC, mod.DST, mod.USER1, mod.USER2), ('', '', '', ''))
        self.assertEqual(mod.ALLOWED_SOURCE_GAPS, ())
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'Konfiguration fehlt'):
                mod.validate_config()

    def test_runtime_and_token_must_be_outside_repo(self):
        with mock.patch.dict(os.environ, self._env(), clear=True), \
             mock.patch.object(mod, 'ROOT', P.parent / 'runtime'):
            with self.assertRaisesRegex(RuntimeError, 'IMAP_WORK_DIR'):
                mod.validate_config()
        with mock.patch.dict(os.environ, self._env(), clear=True), \
             mock.patch.object(mod, 'TOKEN', P.parent / 'token.txt'):
            with self.assertRaisesRegex(RuntimeError, 'IMAP_ACCESS_TOKEN_FILE'):
                mod.validate_config()

    def test_explicit_gap_required(self):
        for invalid in ('not-a-uid', '0', '1,1', '4294967296'):
            with self.subTest(invalid=invalid), mock.patch.dict(os.environ, {'IMAP_ALLOWED_MISSING_UIDS': invalid}):
                with self.assertRaises(RuntimeError):
                    mod.configured_source_gaps()
        with mock.patch.dict(os.environ, {'IMAP_ALLOWED_MISSING_UIDS': '52'}):
            self.assertEqual(mod.configured_source_gaps(), (52,))

    def test_sensitive_helper_output_never_echoed(self):
        fake=mock.Mock(returncode=11,stderr='synthetic-access-token',stdout='synthetic-access-token')
        with tempfile.TemporaryDirectory() as td, mock.patch.object(mod,'ROOT',Path(td)), \
             mock.patch.object(mod.subprocess,'run',return_value=fake):
            with self.assertRaises(RuntimeError) as exc:
                mod.refresh_oauth()
            self.assertIn('Exit 11',str(exc.exception))
            self.assertNotIn('synthetic-access-token',str(exc.exception))

    def test_source_contains_no_real_configuration(self):
        import re
        source=P.read_text()
        self.assertNotRegex(source, r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
        self.assertNotRegex(source, r'/(?:Users|home)/[^\s/\'"]+')
        self.assertNotIn('--delete1',source)
        self.assertNotIn('--delete2',source)
        self.assertNotRegex(source, r'ALLOWED_SOURCE_GAPS\s*=\s*\(\d+')


class FakeImap:
    def logout(self): pass

class Tests(unittest.TestCase):
    def test_bundle_sizes_preserve_all_base_checkpoints(self):
        rows=[(1+600*i,600+600*i,600) for i in range(8)]
        for n, expected_calls in ((1,21),(2,14),(5,7)):
            with self.subTest(bundle=n), contextlib.ExitStack() as stack:
                f=self._make_fixture(rows,completed=[0])
                stack.callback(f[0].cleanup)
                after,calls,_=self._run(f,bundle=n)
                self.assertEqual(len(calls),expected_calls)
                self.assertEqual(sorted(after['completed']),list(range(8)))
                self.assertEqual(after['safe_chunk_next'],{str(i):3 for i in range(1,8)})
                self.assertEqual(sum(t['imapsync_calls'] for t in after['safe_chunk_totals'].values()),expected_calls)

    def test_streaming_log_progress_tracks_chunks_and_heartbeat_delta(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'log.txt'
            p.write_bytes(b'Host1: folder [INBOX] has 100 messages\nmsg INBOX/1 {100} copied to INBOX/99   0.18 msgs/s\n')
            l=mod.LogProgress(p)
            self.assertEqual(l.sample()[0],p.stat().st_size)
            self.assertEqual(l.copied,1)
            self.assertIsNotNone(l.first_copy_at)
            self.assertIsNotNone(l.host1_selected_at)
            self.assertGreater(l.take_heartbeat_delta(),0)
            self.assertEqual(l.take_heartbeat_delta(),0)
            with p.open('ab') as f:f.write(b'msg INBOX/2 {200} copied to INBOX/100   0.23 msgs/s\n')
            l.sample()
            self.assertEqual(l.copied,2)
            self.assertGreater(l.take_heartbeat_delta(),0)

    def test_legacy_log_profile_estimates_only_not_exact(self):
        with tempfile.TemporaryDirectory() as td:
            logdir=Path(td)/'logs'
            logdir.mkdir()
            sample="""Host1: folder [INBOX] selected 200 messages, duplicates 0
msg INBOX/1 {300} copied to INBOX/90    0.20 msgs/s
Messages transferred : 200
Messages skipped : 0
Detected 0 errors
Exiting with return value 0
Transfer time : 20 sec
"""
            (logdir/'p0001-0001-w1-safe-c01-test-try1.log').write_text(sample)
            with mock.patch.object(mod,'LOGS',logdir):
                data=mod.profile_recent_imapsync_logs()
            self.assertEqual(data['sampled'],1)
            self.assertEqual(data['median_first_copy_estimate'],5)
            self.assertEqual(data['avg_duration'],20)

    def test_syntactic_smoke(self):
        import ast
        ast.parse(P.read_text())
        self.assertEqual(mod.SCHEMA, 3)
        self.assertEqual(mod.SAFE_CHUNK, 200)
        self.assertEqual(mod.BUNDLE_CHOICES, (1,2,5))
        self.assertTrue(callable(mod.do_profile))

    def test_controller_uncomparable_still_tests_four(self):
        t=[0.0]
        outputs=[]
        c=mod.AdaptiveParallelismV211(max_workers=4, clock=lambda: t[0],
           stage_seconds=1, min_transferred=1, min_successful_chunks=1,
           output_fn=outputs.append)
        for n, size in ((2,1000),(3,400),(4,1200)):
            self.assertEqual(c.limit,n)
            for lane in range(n):
                self.assertTrue(c.on_chunk_started(lane))
            t[0]+=2
            for lane in range(n):
                c.on_chunk_finished(lane,transferred=10,copied_bytes=size,successful=True)
            c.tick()
        self.assertEqual([r['workers'] for r in c.history],[2,3,4])
        self.assertEqual(c.history[1]['decision'],'not_proven_in_both')
        self.assertEqual(c.limit,4)
        self.assertEqual(c.phase,'selected')

    def test_controller_keeps_two_when_four_not_better_both(self):
        t=[0.0]
        c=mod.AdaptiveParallelismV211(max_workers=4, clock=lambda: t[0],
           stage_seconds=1, min_transferred=1, min_successful_chunks=1,
           output_fn=lambda _ :None)
        for n, size in ((2,1000),(3,400),(4,350)):
            self.assertEqual(c.limit,n)
            for lane in range(n):
                self.assertTrue(c.on_chunk_started(lane))
            t[0]+=2
            for lane in range(n):
                c.on_chunk_finished(lane,transferred=10,copied_bytes=size,successful=True)
            c.tick()
        self.assertEqual(c.limit,2)

    def test_controller_throttling_sticky_and_no_abort(self):
        c=mod.AdaptiveParallelismV211(max_workers=4,benchmark=False,output_fn=lambda _:None)
        gate=mod.ChunkConcurrencyGate(c)
        for lane in range(4):self.assertTrue(gate.acquire(lane))
        c.degrade('serverbackoff',limit=1)
        self.assertEqual(c.limit,1)
        self.assertEqual(set(gate.active),set(range(4)))
        for lane in range(4):gate.release(lane,transferred=1,copied_bytes=100,successful=True)
        self.assertTrue(gate.acquire(3))
        self.assertFalse(c.on_chunk_started(0))
        gate.release(3,transferred=0,copied_bytes=0,successful=True)

    def _make_fixture(self, rows, completed, next_chunks=None, totals=None, missing=None):
        d=tempfile.TemporaryDirectory()
        root=Path(d.name)
        manifest=root/'uid_pakete.tsv'
        manifest.write_text(''.join(f'{a}\t{b}\t{n}\n' for a,b,n in rows))
        original=[uid for a,b,n in rows for uid in range(a,a+n)]
        # fixture rows must consist of consecutive source UIDs
        self.assertTrue(all([b==a+n-1 for a,b,n in rows]))
        state=dict(schema=2,source=mod.SRC,user1=mod.USER1,target=mod.DST,
                   user2=mod.USER2,uidvalidity1='a',uidvalidity2='b',
                   source_uid_sha256=mod.digest_uids(original),
                   manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                   snapshot_count=len(original),snapshot_max_uid=original[-1],
                   initial_target_count=0, pilot_checked=True,parallel_probed=True,
                   completed=list(completed), results={str(i):{'peak_rss_mib':101} for i in completed},
                   attempts={}, in_progress={},probe_results={},safe_chunk_size=200,
                   safe_chunk_next=next_chunks or {},safe_chunk_totals=totals or {},
                   available_processed=[], missing_source={})
        mapping, plan=mod.build_or_validate_lane_plan(state,rows,root/'logs',root)
        state['schema']=3
        state['cache_lane_plan']=plan
        (root/'logs').mkdir(exist_ok=True)
        statepath=root/'migration.json'
        statepath.write_text(json.dumps(state))
        return d,root,manifest,statepath,original,state

    def _run(self, fixture, available_source=None, target_count=None, bundle=5, stop_at=None):
        d,root,manifest,statepath,original,state=fixture
        if available_source is None: available_source=list(original)
        if target_count is None:
            target_count=sum(1 for uid in original if any(
                a<=uid<=b for i,(a,b,n) in enumerate([tuple(map(int,line.split('\t'))) for line in manifest.read_text().splitlines()]) if i in state['completed']))
            target_count+=sum(int(t['transferred']) for t in state.get('safe_chunk_totals',{}).values())
        calls=[]
        counter=[0]
        def fake_execute(ids,lane,rows,pwfile,*,uid_range=None,expected_override=None,log_suffix='',**kwargs):
            self.assertEqual(len(ids),1)
            self.assertEqual(lane,mod.ACTIVE_CACHE_LANES[str(ids[0])])
            expected=[x for x in available_source if uid_range[0]<=x<=uid_range[1]]
            self.assertEqual(expected_override,len(expected))
            self.assertLessEqual(expected_override,bundle*200)
            self.assertTrue(pwfile.exists())
            calls.append((ids[0],lane,uid_range,expected_override,log_suffix))
            counter[0]+=1
            if stop_at is not None and counter[0]>stop_at:
                raise RuntimeError('TEST stop before next transfer')
            return True,dict(transferred=expected_override,skipped=0,selected=expected_override,
              copied_bytes=expected_override*1000,measured_copies=expected_override,
              duration_seconds=20.,peak_rss_mib=100.,log='synthetic.log',
              first_copy_seconds=2.,copy_phase_seconds=15.,post_copy_seconds=3.,
              target_selected_seconds=1.,target_considered_seconds=1.5),1
        with mock.patch.multiple(mod,ROOT=root,MANIFEST=manifest,STATE=statepath,LOGS=root/'logs',
              PROFILE_FILE=root/'performance-v210.jsonl'),\
             mock.patch.object(mod,'verify_identity',return_value=None),\
             mock.patch.object(mod,'source',return_value=FakeImap()),\
             mock.patch.object(mod,'target',return_value=FakeImap()),\
             mock.patch.object(mod,'uidvalidity',return_value='a'),\
             mock.patch.object(mod,'source_uids',return_value=available_source),\
             mock.patch.object(mod,'count',return_value=target_count),\
             mock.patch.object(mod,'guard_cache_before_resume',return_value=None),\
             mock.patch.object(mod,'execute_group',side_effect=fake_execute),\
             contextlib.redirect_stdout(io.StringIO()):
            if stop_at is None:
                mod.run_two_production('synthetic-password',workers=1,bundle_chunks=bundle)
            else:
                with self.assertRaisesRegex(RuntimeError,'TEST stop before next transfer'):
                    mod.run_two_production('synthetic-password',workers=1,bundle_chunks=bundle)
        after=json.loads(statepath.read_text())
        return after,calls,root

    def test_atomic_1000_checkpoint_and_cache_plan_preserved(self):
        rows=[(1+600*i,600+600*i,600) for i in range(8)]
        with contextlib.ExitStack() as stack:
            f=self._make_fixture(rows,completed=[0])
            stack.callback(f[0].cleanup)
            oldmap=f[-1]['cache_lane_plan']['mapping']
            after,calls,root=self._run(f,bundle=5)
            self.assertEqual(len(calls),7)
            self.assertTrue(all(x[3]==600 for x in calls))
            self.assertEqual(after['completed'],list(range(8)))
            self.assertEqual(after['schema'],3)
            self.assertEqual(after['cache_lane_plan']['mapping'],oldmap)
            self.assertEqual(after['snapshot_count'],4800)
            self.assertEqual(sum([after['safe_chunk_totals'][str(i)]['selected'] for i in range(1,8)]),4200)
            self.assertEqual(after['safe_chunk_next'],{str(i):3 for i in range(1,8)})
            self.assertEqual(after['safe_chunk_totals']['1']['chunks'],3)
            self.assertEqual(after['safe_chunk_totals']['1']['imapsync_calls'],1)
            profile=(root/'performance-v210.jsonl').read_text().splitlines()
            self.assertEqual(len(profile),7)
            self.assertEqual(json.loads(profile[0])['bundle_chunks'],3)
            self.assertEqual(after['continuation_version'],'2.11')
            self.assertEqual(after['safe_chunk_size'],200)

    def test_continue_half_completed_packet_and_avoid_resending(self):
        rows=[(1+600*i,600+600*i,600) for i in range(8)]
        # already first 200 of second packet committed, keep its position
        first=dict(transferred=200,skipped=0,selected=200,planned_selected=200,
                   duration_seconds=25.,peak_rss_mib=120.,chunks=1,unavailable_source=0,
                   unavailable_uids=[],last_log='old.log')
        with contextlib.ExitStack() as stack:
            f=self._make_fixture(rows,completed=[0],next_chunks={'1':1},totals={'1':first})
            stack.callback(f[0].cleanup)
            after,calls,root=self._run(f,target_count=800,bundle=5)
            self.assertEqual(calls[0][2],(801,1200))
            self.assertEqual(calls[0][3],400)
            self.assertEqual(after['safe_chunk_next']['1'],3)
            self.assertEqual(after['safe_chunk_totals']['1']['selected'],600)
            self.assertEqual(after['safe_chunk_totals']['1']['chunks'],3)
            self.assertEqual(after['safe_chunk_totals']['1']['imapsync_calls'],1)

    def test_checkpoint_not_advanced_on_interrupt(self):
        rows=[(1+600*i,600+600*i,600) for i in range(8)]
        with contextlib.ExitStack() as stack:
            f=self._make_fixture(rows,completed=[0])
            stack.callback(f[0].cleanup)
            after,calls,root=self._run(f,bundle=5,stop_at=2)
            self.assertEqual(sum(int(x.get('selected',0)) for x in after['safe_chunk_totals'].values()),1200)
            self.assertEqual(sorted(after['completed']),[0,1,4])
            self.assertTrue(after['schema']==3)
            self.assertTrue(len(after['cache_lane_plan']['mapping'])==8)
            self.assertEqual(len((root/'performance-v210.jsonl').read_text().splitlines()),2)
            # Simulate a safe restart from the persisted state, same packet owners.
            after2, new_calls, root = self._run(f, target_count=1800, bundle=5)
            self.assertEqual(sorted(after2['completed']),list(range(8)))
            self.assertTrue(all(c[0] not in (0,1,4) for c in new_calls))

    def test_known_source_gap_stays_open_with_bundling(self):
        rows=[(1,400,400), (501,502,2)]
        with contextlib.ExitStack() as stack:
            f=self._make_fixture(rows,completed=[0])
            stack.callback(f[0].cleanup)
            missing_last=f[4][:-1]
            verify_original = mod.verify_original_snapshot
            def allow_synthetic_gap(state, rows, ids):
                return verify_original(state, rows, ids, allowed_missing=(502,))
            with mock.patch.object(mod, 'verify_original_snapshot', side_effect=allow_synthetic_gap):
                after,calls,root=self._run(f,available_source=missing_last,
                                           target_count=400,bundle=5)
            self.assertEqual(len(calls),1)
            self.assertEqual(calls[0][2],(501,501))
            self.assertEqual(calls[0][3],1)
            self.assertEqual(after['completed'],[0])
            self.assertEqual(after['available_processed'],[1])
            self.assertEqual(after['safe_chunk_totals']['1']['selected'],1)
            self.assertEqual(after['safe_chunk_totals']['1']['unavailable_uids'],[502])
            self.assertEqual(after['missing_source']['502']['status'],'OFFEN')
            self.assertEqual(mod.count_verified_progress(after, rows),401)

    def test_profile_readonly(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'performance-v210.jsonl'
            path.write_text(json.dumps(dict(selected_workers=2,bundle_chunks=5,
                selected=1000,transferred=1000,duration_seconds=120.,
                copied_bytes=100_000,first_copy_seconds=3.))+'\n')
            with mock.patch.object(mod,'PROFILE_FILE',path):
                with contextlib.redirect_stdout(io.StringIO()) as buf:
                    mod.do_profile()
            self.assertIn('2 gleichzeitige Worker',buf.getvalue())
            self.assertIn('3.0s',buf.getvalue())
            self.assertEqual(path.read_text().count('\n'),1)


class TenLaneUpgradeTests(unittest.TestCase):
    def make_case(self, n=100, completed=20):
        root=tempfile.TemporaryDirectory()
        base=Path(root.name)
        rows=[(1+200*i, 200+200*i, 200) for i in range(n)]
        mf=''.join(f'{a}\t{b}\t{c}\n' for a,b,c in rows)
        state=dict(schema=2, manifest_sha256=hashlib.sha256(mf.encode()).hexdigest(),
                   source_uid_sha256=mod.digest_uids(range(1,200*n+1)),
                   snapshot_count=n*200,snapshot_max_uid=n*200,
                   completed=list(range(completed)),results={},
                   safe_chunk_next={},safe_chunk_totals={},attempts={},in_progress={})
        oldmap,oldmeta=mod.build_or_validate_lane_plan(state,rows,base/'logs',base)
        state.update(schema=3,cache_lane_plan=oldmeta)
        return root,base,rows,state,oldmap,oldmeta

    def test_upgrade_only_unstarted_packets_and_immutable_resume(self):
        tmp,base,rows,state,oldmap,oldmeta=self.make_case()
        with tmp:
            new,metadata=mod.upgrade_lane_plan_to_ten(state,rows,base/'logs',base,oldmap,oldmeta)
            self.assertEqual(metadata['version'],2)
            self.assertEqual(len(set(new.values())),10)
            self.assertTrue(metadata['moved_indices'])
            self.assertTrue(all(new[str(i)]==oldmap[str(i)] for i in state['completed']))
            state['cache_lane_plan']=metadata
            again,meta=mod.build_or_validate_lane_plan(state,rows,base/'logs',base)
            self.assertEqual(new,again)
            self.assertEqual(meta,metadata)
            changed=copy.deepcopy(state)
            ix=metadata['moved_indices'][0]
            changed['cache_lane_plan']['mapping'][str(ix)]=oldmap[str(ix)]
            with self.assertRaises(RuntimeError):
                mod._validate_stored_plan(changed,rows,changed['cache_lane_plan'])
            # A cache entry created in a new lane is now recognized on resume.
            ix=next(i for i in metadata['moved_indices'] if new[str(i)] >= 4)
            lane=new[str(ix)]
            self.assertGreaterEqual(lane,4)
            cache=base/f'cache-worker{lane+1}'/'imapsync_cache'
            cache.mkdir(parents=True)
            (cache/f'{rows[ix][0]}_999999').touch()
            again,_=mod.build_or_validate_lane_plan(state,rows,base/'logs',base)
            self.assertEqual(again,new)
            with self.assertRaises(RuntimeError):
                mod.upgrade_lane_plan_to_ten({**state,'cache_lane_plan':oldmeta},rows,base/'logs',base,oldmap,oldmeta)

    def test_upgrade_preserves_unknown_cache_lane_ownership(self):
        tmp,base,rows,state,oldmap,oldmeta=self.make_case()
        with tmp:
            old_lane=oldmap['60']
            cache=base/f'cache-worker{old_lane+1}'/'imapsync_cache'
            cache.mkdir(parents=True)
            (cache/'unparsed_metadata').touch()
            new,meta=mod.upgrade_lane_plan_to_ten(state,rows,base/'logs',base,oldmap,oldmeta)
            for i in range(len(rows)):
                if oldmap[str(i)]==old_lane:
                    self.assertEqual(new[str(i)],old_lane)
            state['cache_lane_plan']=meta
            mod.build_or_validate_lane_plan(state,rows,base/'logs',base)

    def test_controller_tests_ten_then_selects_best(self):
        t=[0.]
        c=mod.AdaptiveParallelismV211(max_workers=10,clock=lambda:t[0],
                   stage_seconds=1,min_successful_chunks=1,min_transferred=1,
                   output_fn=lambda _:None)
        for n in range(2,11):
            self.assertEqual(c.limit,n)
            for lane in range(n):
                self.assertTrue(c.on_chunk_started(lane))
            t[0]+=2
            for lane in range(n):
                # 5 workers best by both rates; 6..10 poorer
                factor=3 if n==5 else (2 if n in (3,4) else 1)
                c.on_chunk_finished(lane,transferred=100*factor,
                                    copied_bytes=100000*factor,successful=True)
            c.tick()
        self.assertEqual(len(c.history),9)
        self.assertEqual(c.limit,5)
        self.assertEqual(c.phase,'selected')

    def test_memory_guard_accepts_ten_and_degrades_without_abort(self):
        c=mod.AdaptiveParallelismV211(max_workers=10,benchmark=False,output_fn=lambda _:None)
        mem=mod.ContinuousMemoryMonitor(workers=10,sample_fn=lambda:dict(
            pressure=4,available_pct=5,swap_used_mib=1000),output_fn=lambda _:None)
        mem.parallel_controller=c
        self.assertTrue(c.on_chunk_started(8))
        mem.check(8888,100)
        self.assertTrue(mem.serial_requested.is_set())
        self.assertEqual(c.limit,1)
        self.assertIn(8,c.active)
        c.on_chunk_finished(8,transferred=100,copied_bytes=1000,successful=True)
        with mod.LOCK:
            mod.RUNNING_RSS_MIB.pop(8888,None)

    def test_10_worker_end_to_end_mock_resume(self):
        rows=[(1+200*i, 200+200*i, 200) for i in range(50)]
        t=Tests()
        f=t._make_fixture(rows,completed=[0])
        d,root,manifest,statepath,original,state=f
        with d:
            seen=[]
            def fake_execute(ids,lane,rows,pwfile,*,uid_range=None,expected_override=None,**kwargs):
                self.assertEqual(mod.ACTIVE_CACHE_LANES[str(ids[0])],lane)
                seen.append((ids[0],lane,expected_override))
                n=expected_override
                return True,dict(transferred=n,skipped=0,selected=n,copied_bytes=n*1000,
                    measured_copies=n,duration_seconds=30.,peak_rss_mib=100.,
                    log='synthetic.log',first_copy_seconds=2.,copy_phase_seconds=25.,
                    post_copy_seconds=3.,target_selected_seconds=1.,
                    target_considered_seconds=1.5),1
            with mock.patch.multiple(mod,ROOT=root,MANIFEST=manifest,STATE=statepath,
                 LOGS=root/'logs',PROFILE_FILE=root/'performance-v210.jsonl'),                 mock.patch.object(mod,'verify_identity',return_value=None),                 mock.patch.object(mod,'source',return_value=FakeImap()),                 mock.patch.object(mod,'target',return_value=FakeImap()),                 mock.patch.object(mod,'uidvalidity',return_value='a'),                 mock.patch.object(mod,'source_uids',return_value=original),                 mock.patch.object(mod,'count',return_value=200),                 mock.patch.object(mod,'guard_cache_before_resume',return_value=None),                 mock.patch.object(mod,'execute_group',side_effect=fake_execute),                 contextlib.redirect_stdout(io.StringIO()):
                mod.run_two_production('synthetic',workers=10,bundle_chunks=5)
            after=json.loads(statepath.read_text())
            self.assertEqual(len(seen),49)
            self.assertEqual({ix for ix,_,_ in seen},set(range(1,50)))
            self.assertEqual(after['completed'],list(range(50)))
            self.assertEqual(after['cache_lane_plan']['version'],2)
            self.assertEqual(len(set(lane for _,lane,_ in seen)),10)
            self.assertEqual(after['snapshot_count'],10000)
            self.assertEqual(after['continuation_version'],'2.11')

if __name__=='__main__':
    unittest.main(verbosity=2)
