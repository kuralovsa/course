// PRE-PATCH tryGetConstantProperty (commit 77a6809, parent of 6471469)
// Source/JavaScriptCore/dfg/DFGGraph.cpp
//
// ЭТО УЯЗВИМОЕ СОСТОЯНИЕ. Ключевые строки (race window):
//
//   Locker cellLock { object->cellLock() };
//   Structure* structure = object->structure();          // <- читает ТЕКУЩУЮ структуру
//   if (!structureSet.toStructureSet().contains(structure))
//       return JSValue();                                 // <- bail, если S2
//   return object->getDirectConcurrently(cellLock, structure, offset);
//                                                          // <- забирает value БЕЗ
//                                                             // повторной проверки на main thread
//
// Race: CFA вызывает это когда structure==S1 (в множестве) -> забирает value из S1.
//       Main thread: delete p2 -> S1->S2.
//       CF вызывает это когда structure==S2 (НЕ в множестве) -> bail.
//       Codegen: CheckStructure S1|S3. Runtime: O=S3 -> PASS -> stale value из S1.

JSValue Graph::tryGetConstantProperty(
    JSValue base, const RegisteredStructureSet& structureSet, PropertyOffset offset)
{
    if (m_plan.isUnlinked())
        return JSValue();

    if (!base || !base.isObject())
        return JSValue();

    JSObject* object = asObject(base);

    for (unsigned i = structureSet.size(); i--;) {
        RegisteredStructure structure = structureSet[i];

        WatchpointSet* set = structure->propertyReplacementWatchpointSet(offset);
        if (!set || !set->isStillValid())
            return JSValue();

        ASSERT(structure->isValidOffset(offset));
        ASSERT(!structure->isUncacheableDictionary());

        watchpoints().addLazily(*set);
    }

    // [комментарий bug 134641: butterfly set before structure, но нет fence]
    // ...

    Locker cellLock { object->cellLock() };
    Structure* structure = object->structure();
    if (!structureSet.toStructureSet().contains(structure))
        return JSValue();

    return object->getDirectConcurrently(cellLock, structure, offset);
}
