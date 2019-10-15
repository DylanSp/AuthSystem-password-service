using ValueOf;

namespace AuthSystemPasswordService
{
    public class PlaintextPassword : ValueOf<string, PlaintextPassword>
    {
    }

    public class Base64Hash : ValueOf<string, Base64Hash>
    {
    }

    public class Base64Salt : ValueOf<string, Base64Salt>
    {
    }

    public class IterationCount : ValueOf<int, IterationCount>
    {
    }

    public class SaltLength : ValueOf<int, SaltLength>
    {
    }

    public class KeyLength : ValueOf<int, KeyLength>
    {
    }
}
