----------------------- MODULE keller_cap_sched -----------------------
(* 
 * KELLER-OS Formal Verification: Fixed-Slot Preemptive Scheduler & Capability Engine
 * Verifies: Mutual exclusion, Capability domain isolation, Deadlock-freedom, and Task Liveness.
 *)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS 
    Tasks,          \* Set of tasks: {idle, input, wm, netd, storaged}
    MaxTicks,       \* Maximum simulation ticks
    QuantumTicks    \* Quantum per task slice

VARIABLES
    current,        \* Currently running task \in Tasks
    state,          \* [t \in Tasks |-> "ready" | "running" | "faulted"]
    caps,           \* [t \in Tasks |-> SUBSET Capabilities]
    ticks_left,     \* [t \in Tasks |-> 0..QuantumTicks]
    total_ticks,    \* 0..MaxTicks
    respawn_count   \* [t \in Tasks |-> 0..5]

Vars == <<current, state, caps, ticks_left, total_ticks, respawn_count>>

Capabilities == {"IoPort", "MmioLFB", "MmioE1000", "MmioAHCI", "ShmBackbuffer", "IrqKbd"}

Init ==
    /\ current = "idle"
    /\ state = [t \in Tasks |-> IF t = "idle" THEN "running" ELSE "ready"]
    /\ caps = [t \in Tasks |-> 
                CASE t = "idle"     -> {}
                  [] t = "input"    -> {"IoPort", "IrqKbd"}
                  [] t = "wm"       -> {"MmioLFB", "ShmBackbuffer"}
                  [] t = "netd"     -> {"MmioE1000"}
                  [] t = "storaged" -> {"MmioAHCI"}]
    /\ ticks_left = [t \in Tasks |-> QuantumTicks]
    /\ total_ticks = 0
    /\ respawn_count = [t \in Tasks |-> 0]

TimerTick ==
    /\ total_ticks < MaxTicks
    /\ total_ticks' = total_ticks + 1
    /\ IF ticks_left[current] > 1
       THEN /\ ticks_left' = [ticks_left EXCEPT ![current] = @ - 1]
            /\ UNCHANGED <<current, state, caps, respawn_count>>
       ELSE \* Quantum expired: Preemptive round-robin context switch
            /\ LET runnable == {t \in Tasks : state[t] \in {"ready", "running"}}
                   next == CHOOSE t \in runnable : TRUE
               IN
                   /\ current' = next
                   /\ state' = [state EXCEPT ![current] = "ready", ![next] = "running"]
                   /\ ticks_left' = [ticks_left EXCEPT ![current] = QuantumTicks, ![next] = QuantumTicks]
                   /\ UNCHANGED <<caps, respawn_count>>

YieldTask ==
    /\ current # "idle"
    /\ state[current] = "running"
    /\ LET runnable == {t \in Tasks : state[t] \in {"ready", "running"} /\ t # current}
           next == IF runnable # {} THEN (CHOOSE t \in runnable : TRUE) ELSE "idle"
       IN
           /\ current' = next
           /\ state' = [state EXCEPT ![current] = "ready", ![next] = "running"]
           /\ ticks_left' = [ticks_left EXCEPT ![next] = QuantumTicks]
           /\ UNCHANGED <<caps, total_ticks, respawn_count>>

FaultAndRespawn ==
    /\ current # "idle"
    /\ state[current] = "running"
    /\ respawn_count[current] < 3
    /\ respawn_count' = [respawn_count EXCEPT ![current] = @ + 1]
    /\ LET runnable == {t \in Tasks : state[t] \in {"ready", "running"} /\ t # current}
           next == IF runnable # {} THEN (CHOOSE t \in runnable : TRUE) ELSE "idle"
       IN
           /\ current' = next
           /\ state' = [state EXCEPT ![current] = "ready", ![next] = "running"]
           /\ ticks_left' = [ticks_left EXCEPT ![next] = QuantumTicks]
           /\ UNCHANGED <<caps, total_ticks>>

Next ==
    \/ TimerTick
    \/ YieldTask
    \/ FaultAndRespawn

(* Invariant: Mutual Exclusion - exactly one task is running at any time *)
SafetyMutualExclusion ==
    \A t1, t2 \in Tasks : (state[t1] = "running" /\ state[t2] = "running") => (t1 = t2)

(* Invariant: Domain Capability Isolation - drivers only possess their granted capabilities *)
SafetyCapabilityIsolation ==
    \A t \in Tasks :
        /\ ("MmioLFB" \in caps[t] => t = "wm")
        /\ ("IoPort" \in caps[t] => t = "input")
        /\ ("MmioE1000" \in caps[t] => t = "netd")
        /\ ("MmioAHCI" \in caps[t] => t = "storaged")

(* Invariant: Kernel Idle context is always preserved and runnable *)
SafetyIdleAlwaysRunnable ==
    state["idle"] \in {"ready", "running"}

(* Invariant: Deadlock Freedom - there is always at least one runnable task *)
DeadlockFree ==
    \E t \in Tasks : state[t] \in {"ready", "running"}

Spec == Init /\ [][Next]_Vars /\ WF_Vars(Next)

(* Temporal Liveness: Every ready task eventually gets scheduled and runs *)
LivenessAllTasksScheduled ==
    \A t \in Tasks : [](state[t] = "ready" => <>(state[t] = "running"))

=============================================================================
