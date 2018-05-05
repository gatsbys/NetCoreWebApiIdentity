using System;

namespace Api.Services.Extensions
{
    public static class Extensions
    {
        public static void CheckArgumentIsNull(this object input, string name)
        {
            if (input == null)
                throw new ArgumentNullException(name);
        }
    }
}
