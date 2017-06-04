using Destiny.Core.IO;
using Destiny.Core.Security;
using System;
using System.Net;
using System.Net.Sockets;

namespace Destiny.Core.Network
{
    public abstract class Session
    {
        public string Host { get; }
        public bool IsAlive { get; private set; }

        private NetworkStream mNetworkStream;

        private readonly Socket mSocket;

        private MapleCryptograph mSendCipher;
        private MapleCryptograph mRecvCipher;

        private byte[] mBuffer;

        private object mLocker;

        protected abstract void Dispatch(byte[] buffer);
        protected abstract void Terminate();

        public Session(Socket socket)
        {
            mSocket = socket;
            mSocket.NoDelay = true;
            mSocket.SendBufferSize = 0xFFFF;
            mSocket.ReceiveBufferSize = 0xFFFF;
            mNetworkStream = new NetworkStream(mSocket);
            mLocker = new object();

            this.Host = (mSocket.RemoteEndPoint as IPEndPoint).Address.ToString();
            this.IsAlive = true;

            mSendCipher = new MapleCryptograph(Constants.Version, Constants.SIV, TransformDirection.Encrypt);
            mRecvCipher = new MapleCryptograph(Constants.Version, Constants.RIV, TransformDirection.Decrypt);

            this.Receive();
        }

        private async void Receive()
        {
            if (!mNetworkStream.CanRead)
            {
                this.Close();
                return;
            }

            while (IsAlive)
            {
                if (!mNetworkStream.DataAvailable) continue;

                var length = 4;
                mBuffer = new byte[length];
                if (await mNetworkStream.ReadAsync(mBuffer, 0, length) == length)
                    length = MapleCryptograph.GetPacketLength(mBuffer);

                if (length > mSocket.ReceiveBufferSize || !mRecvCipher.CheckServerPacket(mBuffer, 0))
                {
                    this.Close();
                    return;
                }

                mBuffer = new byte[length];
                if (await mNetworkStream.ReadAsync(mBuffer, 0, length) == length)
                {
                    mRecvCipher.Transform(mBuffer);
                    Dispatch(mBuffer);
                }
            }
        }

        public void Send(OutPacket oPacket)
        {
            this.Send(oPacket.ToArray());
        }

        public void Send(params byte[][] buffers)
        {
            if (!this.IsAlive)
            {
                return;
            }

            lock (mLocker)
            {
                int length = 0;
                int offset = 0;

                foreach (byte[] buffer in buffers)
                {
                    length += 4;
                    length += buffer.Length;
                }

                byte[] final = new byte[length];

                foreach (byte[] buffer in buffers)
                {
                    mSendCipher.GetHeaderToClient(final, offset, buffer.Length);

                    offset += 4;

                    mSendCipher.Transform(buffer);

                    Buffer.BlockCopy(buffer, 0, final, offset, buffer.Length);

                    offset += buffer.Length;
                }

                this.SendRaw(final);
            }
        }

        public async void SendRaw(byte[] buffer)
        {
            if (!this.IsAlive)
            {
                return;
            }

            await mNetworkStream.WriteAsync(buffer, 0, buffer.Length);
        }

        public void Close()
        {
            if (!this.IsAlive)
            {
                return;
            }

            this.IsAlive = false;

            mSocket.Shutdown(SocketShutdown.Both);
            mSocket.Close();

            if (mSendCipher != null)
            {
                mSendCipher.Dispose();
            }

            if (mRecvCipher != null)
            {
                mRecvCipher.Dispose();
            }

            mBuffer = null;
            mSendCipher = null;
            mRecvCipher = null;

            this.Terminate();
        }
    }
}
