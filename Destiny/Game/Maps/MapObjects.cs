﻿using Destiny.Game.Characters;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Destiny.Game.Maps
{
    public abstract class MapObjects<T> : KeyedCollection<int, T> where T : MapObject
    {
        public Map Map { get; private set; }

        public MapObjects(Map map)
        {
            this.Map = map;
        }

        public IEnumerable<T> GetInRange(MapObject reference, int range)
        {
            foreach (T loopObject in this)
            {
                if (reference.Position.DistanceFrom(loopObject.Position) <= range)
                {
                    yield return loopObject;
                }
            }
        }

        protected override int GetKeyForItem(T item)
        {
            return item.ObjectID;
        }

        protected override void InsertItem(int index, T item)
        {
            item.Map = this.Map;

            if (!(item is Character)  && !(item is Portal))
            {
                item.ObjectID = this.Map.AssignObjectID(item.Type);
            }

            base.InsertItem(index, item);
        }

        protected override void RemoveItem(int index)
        {
            T item = base.Items[index];

            item.Map = null;

            if (!(item is Character) && !(item is Portal))
            {
                item.ObjectID = -1;
            }

            base.RemoveItem(index);
        }
    }
}
