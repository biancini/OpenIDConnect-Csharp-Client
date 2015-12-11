using System.Collections;
using System.Collections.Generic;

namespace OpenIDClient
{
    static class Enumerator
    {
        class GenericEnumeratorAdapter<T> : IEnumerator<T>
        {
            private readonly IEnumerator source;

            public GenericEnumeratorAdapter(IEnumerator source)
            {
                this.source = source;
            }

            public T Current
            {
                get { return (T)source.Current; }
            }

            public void Dispose()
            {
                // Non generic IEnumerator doesn't implement IDisposable so do nothing.
            }

            object System.Collections.IEnumerator.Current
            {
                get
                {
                    return source.Current;
                }
            }

            public bool MoveNext()
            {
                return source.MoveNext();
            }

            public void Reset()
            {
                source.Reset();
            }
        }

        public static IEnumerator<T> AsGeneric<T>(this IEnumerator source)
        {
            return new GenericEnumeratorAdapter<T>(source);
        }
    }
}
